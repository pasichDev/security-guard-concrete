<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\State;

use Concrete\Core\Application\Application;
use Concrete\Core\Database\Connection\Connection;
use PasichDev\SecurityGuard\Config\Settings;
use PasichDev\SecurityGuard\Contract\StateCacheInterface;
use Throwable;

/**
 * Знімок стану для гарячого шляху у state.php (PHP-захист + JSON). Читання —
 * file_get_contents + json_decode, без БД і без opcache. Перебудова — tmp + rename.
 * Якщо файла немає, а перебудувати не вдалося (наприклад, таблиць ще нема),
 * повертаються налаштування за замовчуванням — режим monitor, нічого не блокує.
 */
final class FileStateCache implements StateCacheInterface
{
    private const SEPARATOR = "__halt_compiler();\n";

    /** Пауза між невдалими спробами перебудови з гарячого шляху. */
    private const RETRY_AFTER = 60;

    /** Автоматичні бани перебудовують стан не частіше ніж раз на стільки секунд. */
    public const DEBOUNCE = 15;

    /** @var Application|null */
    private $app;

    /** @var string|null */
    private $dir;

    /** @var array|null */
    private $loaded;

    public function __construct(?Application $app = null, ?string $dir = null)
    {
        $this->app = $app;
        $this->dir = $dir;
    }

    public static function defaults(): array
    {
        return [
            'settings' => Settings::DEFAULTS,
            'blocks' => [],
            'whitelist' => [],
            'builtAt' => 0,
        ];
    }

    public function file(): string
    {
        return $this->dir() . '/state.php';
    }

    public function load(): array
    {
        if ($this->loaded !== null) {
            return $this->loaded;
        }
        $data = $this->read();
        if ($data === null) {
            $data = $this->rebuildFromHotPath();
        } elseif ($this->app !== null && is_file($this->dir() . '/state.dirty')
            && (int) ($data['builtAt'] ?? 0) + self::DEBOUNCE <= time()) {
            // Відкладена перебудова після автоматичних банів.
            $data = $this->rebuildFromHotPath(true) ?? $data;
        }

        return $this->loaded = $data ?? self::defaults();
    }

    /**
     * Перебудова з дебаунсом для автоматичних банів: якщо стан будувався
     * менше DEBOUNCE секунд тому — лише позначка «застарів», перебудує
     * наступний запит після паузи. Ручні дії викликають rebuild() одразу.
     */
    public function rebuildDebounced(): void
    {
        $builtAt = (int) ($this->read()['builtAt'] ?? 0);
        if ($builtAt + self::DEBOUNCE <= time()) {
            $this->rebuild();

            return;
        }
        StateDir::prepare($this->dir());
        @touch($this->dir() . '/state.dirty');
        $this->loaded = null;
    }

    /** Діапазони IP ботів із SecurityGuardBotRanges (окремий файл, читається лише для запитів з UA пошуковика). */
    public function botRanges(): array
    {
        $raw = @file_get_contents($this->dir() . '/botranges.php');
        if (!is_string($raw) || ($pos = strpos($raw, self::SEPARATOR)) === false) {
            return [];
        }
        $data = json_decode(substr($raw, $pos + strlen(self::SEPARATOR)), true);

        return is_array($data) ? $data : [];
    }

    public function rebuild(): void
    {
        $this->write($this->collect());
    }

    public function clear(): void
    {
        $this->loaded = null;
        $file = $this->file();
        if (is_file($file)) {
            @unlink($file);
            $this->invalidate($file);
        }
        StateDir::remove($this->dir());
    }

    /** Записує вже зібраний масив стану (використовується й тестами). */
    public function write(array $data): void
    {
        $data += self::defaults();
        $data['builtAt'] = time();
        $dir = $this->dir();
        StateDir::prepare($dir);
        $file = $this->file();
        $json = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($json === false) {
            throw new \RuntimeException('Security Guard: cannot encode state');
        }
        // PHP-оболонка лише для захисту від прямого відкриття; дані — JSON після SEPARATOR.
        $php = "<?php\n// Security Guard: знімок стану, перебудовується пакетом; не редагувати.\n"
            . "defined('C5_EXECUTE') or die('Access Denied.');\n" . self::SEPARATOR . $json . "\n";
        $tmp = $file . '.' . bin2hex(random_bytes(6)) . '.tmp';
        if (@file_put_contents($tmp, $php, LOCK_EX) === false) {
            throw new \RuntimeException('Security Guard: cannot write state file in ' . $dir);
        }
        @chmod($tmp, 0640);
        if (!@rename($tmp, $file)) {
            @unlink($tmp);
            throw new \RuntimeException('Security Guard: cannot replace state file in ' . $dir);
        }
        $this->invalidate($file);
        @unlink($dir . '/rebuild.failed');
        @unlink($dir . '/state.dirty');
        $this->loaded = $data;
    }

    private function dir(): string
    {
        return $this->dir ?? StateDir::path();
    }

    private function read(): ?array
    {
        $file = $this->file();
        if (!is_file($file)) {
            return null;
        }
        // Не include: opcache у веб-процесі не бачить перебудови з CLI/cron
        // (validate_timestamps=0 чи revalidate_freq), тож читаємо файл напряму.
        $raw = @file_get_contents($file);
        if (!is_string($raw)) {
            return null;
        }
        $pos = strpos($raw, self::SEPARATOR);
        if ($pos === false) {
            return null;
        }
        try {
            $data = json_decode(substr($raw, $pos + strlen(self::SEPARATOR)), true, 64, JSON_THROW_ON_ERROR);
        } catch (Throwable $e) {
            return null;
        }
        if (!is_array($data) || !isset($data['settings']) || !is_array($data['settings'])) {
            return null;
        }
        $data['settings'] += Settings::DEFAULTS;
        $data += self::defaults();

        return $data;
    }

    /** Одна спроба під неблокуючим замком; невдача — пауза RETRY_AFTER секунд. */
    private function rebuildFromHotPath(bool $dirty = false): ?array
    {
        if ($this->app === null) {
            return null;
        }
        $dir = $this->dir();
        $failed = $dir . '/rebuild.failed';
        $mtime = @filemtime($failed);
        if (!$dirty && $mtime !== false && $mtime > time() - self::RETRY_AFTER) {
            return null;
        }
        StateDir::prepare($dir);
        $lock = @fopen($dir . '/rebuild.lock', 'c');
        if ($lock === false) {
            return null;
        }
        try {
            if (!flock($lock, LOCK_EX | LOCK_NB)) {
                return null;
            }
            try {
                $this->rebuild();

                return $this->loaded;
            } catch (Throwable $e) {
                @touch($failed);
                $this->logError($e);

                return null;
            } finally {
                flock($lock, LOCK_UN);
            }
        } finally {
            fclose($lock);
        }
    }

    private function collect(): array
    {
        if ($this->app === null) {
            throw new \RuntimeException('Security Guard: application is not available');
        }
        $now = time();
        $settings = $this->app->make(Settings::class)->all();
        // Секрет аварійного обходу не кладемо у файл відкритим текстом — лише хеш.
        $token = (string) $settings['bypass_token'];
        $settings['bypass_token'] = '';
        $settings['bypass_token_hash'] = $token === '' ? '' : hash('sha256', $token);
        /** @var Connection $db */
        $db = $this->app->make(Connection::class);

        $blocks = [];
        $rows = $db->fetchAllAssociative(
            'SELECT ip, reason, category, blockedUntil, permanent, manual FROM SecurityGuardBlocks WHERE permanent = 1 OR blockedUntil > ?',
            [$now]
        );
        foreach ($rows as $row) {
            $blocks[(string) $row['ip']] = [
                'until' => (int) $row['permanent'] ? 0 : (int) $row['blockedUntil'],
                'reason' => (string) $row['reason'],
                'category' => (string) $row['category'],
                'manual' => (bool) (int) $row['manual'],
            ];
        }

        $whitelist = [];
        $rows = $db->fetchAllAssociative(
            'SELECT ipRange, expiresAt, auto FROM SecurityGuardWhitelist WHERE expiresAt = 0 OR expiresAt > ?',
            [$now]
        );
        foreach ($rows as $row) {
            $whitelist[] = ['range' => (string) $row['ipRange'], 'expires' => (int) $row['expiresAt'], 'auto' => (bool) (int) $row['auto']];
        }
        $this->writeBotRanges();

        return [
            'settings' => $settings,
            'blocks' => $blocks,
            'whitelist' => $whitelist,
            'builtAt' => $now,
        ];
    }

    /** Діапазони ботів — окремим файлом, щоб не роздувати state.php, який читається на кожному запиті. */
    private function writeBotRanges(): void
    {
        try {
            $ranges = (new \PasichDev\SecurityGuard\Update\BotRangeStore($this->app->make(Connection::class)))->rangesByBot();
            $file = $this->dir() . '/botranges.php';
            if ($ranges === []) {
                @unlink($file);

                return;
            }
            $php = "<?php\ndefined('C5_EXECUTE') or die('Access Denied.');\n" . self::SEPARATOR . json_encode($ranges, JSON_UNESCAPED_SLASHES) . "\n";
            $tmp = $file . '.' . bin2hex(random_bytes(6)) . '.tmp';
            if (@file_put_contents($tmp, $php, LOCK_EX) !== false && !@rename($tmp, $file)) {
                @unlink($tmp);
            }
        } catch (Throwable $e) {
            // Без збережених діапазонів працюють вбудовані.
        }
    }

    private function invalidate(string $file): void
    {
        clearstatcache(true, $file);
        if (function_exists('opcache_invalidate')) {
            @opcache_invalidate($file, true);
        }
    }

    private function logError(Throwable $e): void
    {
        try {
            if ($this->app !== null) {
                $this->app->make('log')->warning('Security Guard: state rebuild failed: ' . $e->getMessage());
            }
        } catch (Throwable $ignored) {
        }
    }
}
