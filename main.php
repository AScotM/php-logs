<?php

declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '1');

class SecurityError extends Exception {
    public function __construct(string $message = "") {
        parent::__construct($message);
    }
}

class CommandTimeoutError extends Exception {
    public function __construct(string $message = "") {
        parent::__construct($message);
    }
}

class FileWrapper {
    protected $handle;
    
    public function __construct($handle) {
        $this->handle = $handle;
    }
    
    public function gets(): ?string {
        $line = fgets($this->handle);
        return $line === false ? null : $line;
    }
    
    public function close(): void {
        fclose($this->handle);
    }
}

class GzFileWrapper extends FileWrapper {
    public function gets(): ?string {
        $line = gzgets($this->handle);
        return $line === false ? null : $line;
    }
    
    public function close(): void {
        gzclose($this->handle);
    }
}

class BzFileWrapper extends FileWrapper {
    public function gets(): ?string {
        $line = bzgets($this->handle);
        return $line === false ? null : $line;
    }
    
    public function close(): void {
        bzclose($this->handle);
    }
}

class RSyslogInfo {
    public string $version = "";
    public array $features = [];
    public string $configFile = "";
    public string $pidFile = "";
    public string $platform = "";
    public int $rainerscriptBits = 0;

    public function detectRSyslogInfo(): bool {
        $output = $this->executeWithTimeout("rsyslogd -v 2>&1", 3);
        if ($output !== null && trim($output) !== "") {
            return $this->parseVersionOutput($output);
        }
        return $this->detectFromSystem();
    }

    private function executeWithTimeout(string $command, int $timeout = 5): ?string {
        $descriptorspec = [
            0 => ["pipe", "r"],
            1 => ["pipe", "w"],
            2 => ["pipe", "w"]
        ];
        
        $process = proc_open($command, $descriptorspec, $pipes);
        if (!is_resource($process)) {
            return null;
        }
        
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        
        $output = '';
        $start = time();
        
        while (true) {
            $status = proc_get_status($process);
            if (!$status['running']) {
                break;
            }
            
            if (time() - $start > $timeout) {
                proc_terminate($process, 9);
                foreach ($pipes as $pipe) {
                    fclose($pipe);
                }
                proc_close($process);
                throw new CommandTimeoutError("Command timed out: " . $command);
            }
            
            $output .= stream_get_contents($pipes[1]);
            usleep(10000);
        }
        
        $output .= stream_get_contents($pipes[1]);
        
        foreach ($pipes as $pipe) {
            fclose($pipe);
        }
        proc_close($process);
        
        return $output;
    }

    private function parseVersionOutput(string $output): bool {
        $lines = explode("\n", trim($output));
        if (empty($lines)) {
            return false;
        }

        if (preg_match('/rsyslogd\s+([\d.]+)/', $lines[0], $matches)) {
            $this->version = $matches[1];
        }

        foreach ($lines as $line) {
            $line = trim($line);

            if (str_starts_with($line, "Config file:")) {
                $parts = explode(":", $line, 2);
                if (count($parts) === 2) {
                    $this->configFile = trim($parts[1]);
                }
            } elseif (str_starts_with($line, "PID file:")) {
                $parts = explode(":", $line, 2);
                if (count($parts) === 2) {
                    $this->pidFile = trim($parts[1]);
                }
            } elseif (str_contains($line, "Number of Bits in RainerScript integers:")) {
                if (preg_match('/(\d+)/', $line, $matches)) {
                    $this->rainerscriptBits = (int)$matches[1];
                }
            } elseif (str_contains($line, ":") && (str_contains($line, "Yes") || str_contains($line, "No"))) {
                $parts = explode(":", $line, 2);
                if (count($parts) === 2) {
                    $feature = trim($parts[0]);
                    $value = str_contains($parts[1], "Yes");
                    $this->features[$feature] = $value;
                }
            }
        }

        return true;
    }

    private function detectFromSystem(): bool {
        try {
            $output = $this->executeWithTimeout("pgrep rsyslog 2>&1", 3);
        } catch (CommandTimeoutError $e) {
            return false;
        }
        
        if ($output !== null && trim($output) !== "") {
            $this->version = "unknown (running)";

            $possibleConfigs = [
                "/etc/rsyslog.conf",
                "/etc/rsyslog.d/",
                "/usr/local/etc/rsyslog.conf",
            ];
            foreach ($possibleConfigs as $config) {
                if (file_exists($config)) {
                    $this->configFile = $config;
                    break;
                }
            }
            return true;
        }
        return false;
    }

    public function versionCompare(string $v1, string $v2): int {
        $normalize = function(string $v): array {
            $clean = preg_replace('/[^0-9.]/', '', $v);
            $parts = explode(".", $clean);
            $result = [];
            foreach ($parts as $part) {
                $result[] = (int)$part;
            }
            return $result;
        };

        $v1Norm = $normalize($v1);
        $v2Norm = $normalize($v2);

        $maxLen = max(count($v1Norm), count($v2Norm));

        for ($i = 0; $i < $maxLen; $i++) {
            $v1Part = $v1Norm[$i] ?? 0;
            $v2Part = $v2Norm[$i] ?? 0;
            if ($v1Part !== $v2Part) {
                return $v1Part - $v2Part;
            }
        }
        return 0;
    }

    public function getConfigRecommendations(): array {
        $recommendations = [];

        if ($this->version !== "" && $this->versionCompare($this->version, "8.0") < 0) {
            $recommendations["version"] = "Consider upgrading to rsyslog 8.x+ for better features";
        }

        if (!($this->features["FEATURE_REGEXP"] ?? false)) {
            $recommendations["regexp"] = "Rebuild rsyslog with regexp support for better parsing";
        }

        if ($this->configFile !== "" && file_exists($this->configFile) && is_file($this->configFile)) {
            $content = file_get_contents($this->configFile);
            if ($content !== false) {
                if (!str_contains($content, "imfile")) {
                    $recommendations["imfile"] = "Consider enabling imfile module for file monitoring";
                }
                if (str_contains($content, "omelasticsearch")) {
                    $recommendations["elastic"] = "Elasticsearch output detected - consider using elastic tools";
                }
            }
        }

        return $recommendations;
    }
}

class PatternInfo {
    private string $pattern;
    private string $type;
    private string $description;
    
    public function __construct(string $pattern, string $type, string $description) {
        $this->pattern = $pattern;
        $this->type = $type;
        $this->description = $description;
    }
    
    public function getPattern(): string {
        return $this->pattern;
    }
    
    public function getType(): string {
        return $this->type;
    }
    
    public function getDescription(): string {
        return $this->description;
    }
}

class LogEntry {
    public DateTime $timestamp;
    public string $service;
    public string $message;
    public string $level;
    public string $host;
    public string $pid;
    public string $rawLine;

    public function __construct() {
        $this->timestamp = new DateTime();
        $this->service = "";
        $this->message = "";
        $this->level = "";
        $this->host = "";
        $this->pid = "";
        $this->rawLine = "";
    }

    public function isError(): bool {
        if ($this->level !== "") {
            $upperLevel = strtoupper($this->level);
            return $upperLevel === "ERROR" || $upperLevel === "CRITICAL" || $upperLevel === "FATAL";
        }
        $errorIndicators = ["error", "failed", "failure", "exception", "critical", "panic"];
        $lowerMessage = strtolower($this->message);
        foreach ($errorIndicators as $indicator) {
            if (str_contains($lowerMessage, $indicator)) {
                return true;
            }
        }
        return false;
    }
}

class AnalysisResults {
    public int $totalEntries = 0;
    public array $uniqueServices = [];
    public array $dateRange = ["", ""];
    public array $serviceCounts = [];
    public int $errorCount = 0;
    public array $levelDistribution = [];
    public array $hourlyDistribution = [];

    public function update(LogEntry $entry): void {
        $this->totalEntries++;
        $this->uniqueServices[$entry->service] = true;
        $this->serviceCounts[$entry->service] = ($this->serviceCounts[$entry->service] ?? 0) + 1;
        
        if ($entry->level !== "") {
            $upperLevel = strtoupper($entry->level);
            $this->levelDistribution[$upperLevel] = ($this->levelDistribution[$upperLevel] ?? 0) + 1;
        }
        
        if ($entry->isError()) {
            $this->errorCount++;
        }
        
        $hourKey = $entry->timestamp->format("H:00");
        $this->hourlyDistribution[$hourKey] = ($this->hourlyDistribution[$hourKey] ?? 0) + 1;
        
        if ($this->dateRange[0] === "" || $entry->timestamp->format("Y-m-d") < $this->dateRange[0]) {
            $this->dateRange[0] = $entry->timestamp->format("Y-m-d");
        }
        if ($this->dateRange[1] === "" || $entry->timestamp->format("Y-m-d") > $this->dateRange[1]) {
            $this->dateRange[1] = $entry->timestamp->format("Y-m-d");
        }
    }
}

class ErrorClusterPlugin {
    private array $errorPatterns = [];
    private array $serviceErrors = [];

    public function processEntry(LogEntry $entry): void {
        if (!$entry->isError()) {
            return;
        }

        $pattern = $this->extractErrorPattern($entry->message);
        $this->errorPatterns[$pattern] = ($this->errorPatterns[$pattern] ?? 0) + 1;
        
        if (!isset($this->serviceErrors[$entry->service])) {
            $this->serviceErrors[$entry->service] = [];
        }
        $this->serviceErrors[$entry->service][$pattern] = ($this->serviceErrors[$entry->service][$pattern] ?? 0) + 1;
    }

    private function extractErrorPattern(string $message): string {
        $words = preg_split('/\s+/', $message);
        if ($words === false) {
            return $message;
        }
        if (count($words) > 3) {
            return implode(" ", array_slice($words, 0, 3)) . "...";
        }
        return $message;
    }

    public function getResults(): array {
        $topPatterns = [];
        $patterns = array_keys($this->errorPatterns);
        usort($patterns, fn($a, $b) => $this->errorPatterns[$b] <=> $this->errorPatterns[$a]);
        
        $maxPatterns = 10;
        $count = 0;
        foreach ($patterns as $pattern) {
            if ($count >= $maxPatterns) break;
            $topPatterns[$pattern] = $this->errorPatterns[$pattern];
            $count++;
        }
        
        $serviceErrors = [];
        foreach ($this->serviceErrors as $service => $patterns) {
            $serviceErrors[$service] = $patterns;
        }
        
        return [
            "top_error_patterns" => $topPatterns,
            "service_errors" => $serviceErrors
        ];
    }
}

class BoundedLogStorage {
    private array $entries = [];
    private int $maxSize;
    private int $head = 0;
    private int $tail = 0;
    private int $size = 0;

    public function __construct(int $maxSize) {
        $this->maxSize = $maxSize;
        $this->entries = array_fill(0, $maxSize, null);
    }

    public function add(LogEntry $entry): void {
        $this->entries[$this->tail] = $entry;
        $this->tail = ($this->tail + 1) % $this->maxSize;
        
        if ($this->size < $this->maxSize) {
            $this->size++;
        } else {
            $this->entries[$this->head] = null;
            $this->head = ($this->head + 1) % $this->maxSize;
        }
    }

    public function getAll(): array {
        $result = [];
        if ($this->size > 0) {
            if ($this->head < $this->tail) {
                for ($i = $this->head; $i < $this->tail; $i++) {
                    if ($this->entries[$i] !== null) {
                        $result[] = $this->entries[$i];
                    }
                }
            } else {
                for ($i = $this->head; $i < $this->maxSize; $i++) {
                    if ($this->entries[$i] !== null) {
                        $result[] = $this->entries[$i];
                    }
                }
                for ($i = 0; $i < $this->tail; $i++) {
                    if ($this->entries[$i] !== null) {
                        $result[] = $this->entries[$i];
                    }
                }
            }
        }
        return $result;
    }

    public function size(): int {
        return $this->size;
    }
}

class ConcurrentTree {
    private array $tree = [];

    public function addEntry(string $date, string $service, LogEntry $entry): void {
        if (!isset($this->tree[$date])) {
            $this->tree[$date] = [];
        }
        if (!isset($this->tree[$date][$service])) {
            $this->tree[$date][$service] = [];
        }
        $this->tree[$date][$service][] = $entry;
    }

    public function getTree(): array {
        return $this->tree;
    }

    public function getDates(): array {
        return array_keys($this->tree);
    }
}

class LogParser {
    private int $currentYear;
    private bool $verbose;
    private bool $useRSyslogDetection;
    private ?RSyslogInfo $rsyslogInfo = null;
    private array $patternDefinitions = [];
    private array $compiledRegexes = [];
    private array $months = [
        "Jan" => 1, "Feb" => 2, "Mar" => 3, "Apr" => 4, "May" => 5, "Jun" => 6,
        "Jul" => 7, "Aug" => 8, "Sep" => 9, "Oct" => 10, "Nov" => 11, "Dec" => 12
    ];
    private array $monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

    public function __construct(int $currentYear, bool $verbose, bool $useRSyslogDetection) {
        $this->currentYear = $currentYear;
        $this->verbose = $verbose;
        $this->useRSyslogDetection = $useRSyslogDetection;
        
        if ($useRSyslogDetection) {
            $this->rsyslogInfo = new RSyslogInfo();
            try {
                if ($this->rsyslogInfo->detectRSyslogInfo() && $verbose) {
                    echo "Detected rsyslogd version: " . $this->rsyslogInfo->version . PHP_EOL;
                }
            } catch (CommandTimeoutError $e) {
                if ($verbose) {
                    echo "RSyslog detection timed out" . PHP_EOL;
                }
            }
        }
        
        $this->patternDefinitions = $this->initializePatternDefinitions();
        $this->compileRegexes();
    }

    private function initializePatternDefinitions(): array {
        return [
            new PatternInfo(
                '/^(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+' .
                '(?P<day>\d{1,2})\s+' .
                '(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+' .
                '(?P<host>[\w\-.]+)\s+' .
                '(?P<service>[\w\-.\\/]+)(?:\[(?P<pid>\d+)\])?:\s*' .
                '(?:\[(?P<level>\w+)\]\s*)?' .
                '(?P<message>.+)$/',
                "traditional",
                "Traditional syslog format"
            ),
            new PatternInfo(
                '/^(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+' .
                '(?P<day>\d{1,2})\s+' .
                '(?P<time>\d{2}:\d{2}:\d{2})\s+' .
                '(?P<host>[\w\-.]+)\s+' .
                '(?P<service>[\w\-.\\/]+):\s*' .
                '(?P<message>.+)$/',
                "traditional_simple",
                "Simple syslog format"
            ),
            new PatternInfo(
                '/^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?(?:\s+[+-]\d{4})?)\s+' .
                '(?P<host>[\w\-.]+)\s+' .
                '(?P<service>[\w\-.\\/]+)(?:\[(?P<pid>\d+)\])?:\s*' .
                '(?:\[(?P<level>\w+)\]\s*)?' .
                '(?P<message>.+)$/',
                "iso8601",
                "ISO 8601 timestamp format"
            ),
            new PatternInfo(
                '/^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{4})\s+' .
                '(?P<host>[\w\-.]+)\s+' .
                '(?P<service>\w+)\[(?P<pid>\d+)\]:\s*' .
                '(?P<message>.+)$/',
                "journald",
                "Journald-style format"
            ),
            new PatternInfo(
                '/^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[\d+-:]+)\s+' .
                '(?P<host>\S+)\s+' .
                '(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?:?\s+' .
                '(?:\[(?P<level>\w+)\]\s+)?' .
                '(?P<message>.+)$/',
                "rainerscript_enhanced",
                "RainerScript enhanced format"
            )
        ];
    }

    private function compileRegexes(): void {
        foreach ($this->patternDefinitions as $patternInfo) {
            $regex = $patternInfo->getPattern();
            if (@preg_match($regex, '') !== false) {
                $this->compiledRegexes[] = [
                    'pattern' => $regex,
                    'type' => $patternInfo->getType()
                ];
            }
        }
    }

    public function parseLine(string $line, DateTime $now, DateTime $cutoffDate): ?LogEntry {
        $line = trim($line);
        if (!$this->isLikelyLogLine($line)) {
            return null;
        }
        
        foreach ($this->compiledRegexes as $regexInfo) {
            if (!preg_match($regexInfo['pattern'], $line, $matches)) {
                continue;
            }
            
            $groupDict = [];
            foreach ($matches as $key => $value) {
                if (is_string($key) && $value !== "") {
                    $groupDict[$key] = $value;
                }
            }
            
            $timestamp = $this->extractTimestamp($groupDict, $regexInfo['type'], $now);
            if ($timestamp === null || $timestamp < $cutoffDate || $timestamp > (clone $now)->modify('+24 hours')) {
                return null;
            }
            
            $entry = new LogEntry();
            $entry->timestamp = $timestamp;
            $entry->service = trim($groupDict["service"] ?? "");
            $entry->message = trim($groupDict["message"] ?? "");
            $entry->level = $groupDict["level"] ?? "";
            $entry->host = $groupDict["host"] ?? "";
            $entry->pid = $groupDict["pid"] ?? "";
            $entry->rawLine = $line;
            
            return $entry;
        }
        
        return null;
    }

    private function isLikelyLogLine(string $line): bool {
        if ($line === "" || strlen($line) < 10) {
            return false;
        }
        
        $firstThree = substr($line, 0, 3);
        if (in_array($firstThree, $this->monthNames, true)) {
            return true;
        }
        
        return preg_match('/^\d{4}-\d{2}-\d{2}/', $line) === 1;
    }

    private function extractTimestamp(array $groupDict, string $patternType, DateTime $now): ?DateTime {
        if (isset($groupDict["timestamp"])) {
            $dt = $this->parseIsoTimestamp($groupDict["timestamp"]);
            if ($dt !== null) {
                return $dt;
            }
        }
        
        if (isset($groupDict["month"], $groupDict["day"], $groupDict["time"])) {
            return $this->parseTraditionalTimestamp(
                $groupDict["month"],
                $groupDict["day"],
                $groupDict["time"],
                $now
            );
        }
        
        return null;
    }

    private function parseTraditionalTimestamp(string $month, string $day, string $timeStr, DateTime $now): ?DateTime {
        $monthNum = $this->months[$month] ?? 0;
        if ($monthNum === 0) {
            return null;
        }
        
        $year = $this->currentYear;
        
        $nowMonth = (int)$now->format('n');
        $nowDay = (int)$now->format('j');
        
        if ($monthNum > $nowMonth || ($monthNum === $nowMonth && (int)$day > $nowDay)) {
            $year--;
        }
        
        $baseTime = $timeStr;
        $microseconds = 0;
        
        if (str_contains($timeStr, '.')) {
            $parts = explode('.', $timeStr, 2);
            $baseTime = $parts[0];
            $microPart = $parts[1];
            
            $microPart = substr($microPart, 0, 6);
            $microPart = str_pad($microPart, 6, '0');
            $microseconds = (int)$microPart;
        }
        
        try {
            $dateStr = sprintf('%d-%02d-%02d %s', $year, $monthNum, (int)$day, $baseTime);
            $dt = DateTime::createFromFormat('Y-m-d H:i:s', $dateStr);
            
            if ($dt === false) {
                return null;
            }
            
            if ($microseconds > 0) {
                $dt = DateTime::createFromFormat('Y-m-d H:i:s.u', $dt->format('Y-m-d H:i:s') . '.' . str_pad((string)$microseconds, 6, '0'));
            }
            
            return $dt;
        } catch (Exception $e) {
            return null;
        }
    }

    private function parseIsoTimestamp(string $tsStr): ?DateTime {
        $tsStr = str_replace(' ', 'T', $tsStr);
        
        $formats = [
            'Y-m-d\TH:i:s.uP',
            'Y-m-d\TH:i:sP',
            'Y-m-d\TH:i:s.u',
            'Y-m-d\TH:i:s',
            'Y-m-d\TH:i:s.u\Z',
            'Y-m-d\TH:i:s\Z',
        ];
        
        foreach ($formats as $format) {
            $dt = DateTime::createFromFormat($format, $tsStr);
            if ($dt !== false) {
                return $dt;
            }
        }
        
        return null;
    }
    
    public function getRSyslogInfo(): ?RSyslogInfo {
        return $this->rsyslogInfo;
    }
    
    public function getPatternCount(): int {
        return count($this->patternDefinitions);
    }
}

class RSyslogAnalyzer {
    private const DEFAULT_SYSLOG_PATHS = [
        "/var/log/messages",
        "/var/log/syslog",
        "/var/log/system.log",
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/kern.log",
        "/var/log/dmesg",
        "/var/log/debug",
        "/var/log/journal",
        "/run/log"
    ];
    
    private const ALLOWED_DIRS = [
        "/var/log", 
        "/tmp/logs", 
        "/opt/logs",
        "/var/log/journal",
        "/run/log"
    ];
    
    private const RECENT_DAYS_COUNT = 7;
    private const MAX_TOP_SERVICES = 5;
    private const MEMORY_LIMIT_BYTES = 256 * 1024 * 1024;
    
    private ConcurrentTree $tree;
    private array $config;
    private string $logFile;
    private int $currentYear;
    private LogParser $parser;
    private AnalysisResults $analysisResults;
    private array $plugins;
    private int $processedLines = 0;
    private int $parsedEntries = 0;
    private bool $memoryWarning = false;
    private BoundedLogStorage $storage;

    public function __construct(string $logFile, array $config) {
        $this->config = array_merge([
            'max_days' => 30,
            'truncate_length' => 80,
            'show_full_lines' => false,
            'wrap_lines' => false,
            'max_lines_per_service' => 5,
            'color_output' => true,
            'verbose' => false,
            'enable_analysis' => false,
            'max_file_size_mb' => 100,
            'use_rsyslog_detection' => true,
            'max_memory_entries' => 100000,
        ], $config);
        
        $this->tree = new ConcurrentTree();
        $this->logFile = $logFile;
        $this->currentYear = (int)date('Y');
        $this->parser = new LogParser($this->currentYear, $this->config['verbose'], $this->config['use_rsyslog_detection']);
        $this->analysisResults = new AnalysisResults();
        $this->plugins = [new ErrorClusterPlugin()];
        $this->storage = new BoundedLogStorage($this->config['max_memory_entries']);
        
        if ($this->logFile === "") {
            $this->logFile = $this->findLogFile();
        }
    }

    private function findLogFile(): string {
        $candidates = [];
        
        foreach (self::DEFAULT_SYSLOG_PATHS as $path) {
            if ($this->isReadableLog($path)) {
                $mtime = filemtime($path);
                if ($mtime !== false) {
                    $candidates[] = ['path' => $path, 'mtime' => $mtime];
                }
            }
            
            for ($i = 0; $i <= 3; $i++) {
                $pattern = $path . "." . $i;
                if ($this->isReadableLog($pattern)) {
                    $mtime = filemtime($pattern);
                    if ($mtime !== false) {
                        $candidates[] = ['path' => $pattern, 'mtime' => $mtime];
                    }
                }
            }
            
            $recentDates = $this->getRecentDates();
            foreach ($recentDates as $date) {
                $pattern = $path . "-" . $date;
                if ($this->isReadableLog($pattern)) {
                    $mtime = filemtime($pattern);
                    if ($mtime !== false) {
                        $candidates[] = ['path' => $pattern, 'mtime' => $mtime];
                    }
                }
            }
        }
        
        foreach ($candidates as $candidate) {
            foreach ([".gz", ".bz2"] as $ext) {
                $compressedPath = $candidate['path'] . $ext;
                if ($this->isReadableLog($compressedPath)) {
                    $mtime = filemtime($compressedPath);
                    if ($mtime !== false) {
                        $candidates[] = ['path' => $compressedPath, 'mtime' => $mtime];
                    }
                }
            }
        }
        
        if (empty($candidates)) {
            if ($this->config['verbose']) {
                echo "No standard syslog file found or insufficient permissions\n";
            }
            return "";
        }
        
        usort($candidates, fn($a, $b) => $b['mtime'] <=> $a['mtime']);
        
        $selected = $candidates[0]['path'];
        if ($this->config['verbose']) {
            echo "Using log file: " . $selected . PHP_EOL;
        }
        return $selected;
    }

    private function getRecentDates(): array {
        $dates = [];
        for ($i = 0; $i < self::RECENT_DAYS_COUNT; $i++) {
            $dates[] = date("Ymd", strtotime("-$i days"));
        }
        return $dates;
    }

    private function isReadableLog(string $path): bool {
        return is_file($path) && is_readable($path);
    }

    public function loadLogs(): void {
        if ($this->logFile === "") {
            throw new Exception("No log file specified or found");
        }
        
        if (!file_exists($this->logFile)) {
            throw new Exception("Log file does not exist: " . $this->logFile);
        }
        
        $info = stat($this->logFile);
        if ($info === false) {
            throw new Exception("Cannot access log file");
        }
        
        $fileSize = $info['size'];
        $fileSizeMB = $fileSize / (1024 * 1024);
        
        if ($fileSizeMB > $this->config['max_file_size_mb']) {
            throw new SecurityError(sprintf(
                "File too large: %.1fMB > %dMB limit", 
                $fileSizeMB, 
                $this->config['max_file_size_mb']
            ));
        }
        
        if ($fileSizeMB > 10 && $this->config['verbose']) {
            echo "Parsing logs (this may take a while)...";
            flush();
        }
        
        $wrapper = $this->openLogFile($this->logFile);
        
        $now = new DateTime();
        $cutoffDate = clone $now;
        $cutoffDate->modify("-" . $this->config['max_days'] . " days");
        
        while (($line = $wrapper->gets()) !== null) {
            $this->processedLines++;
            
            if ($this->processedLines % 10000 === 0) {
                $this->checkMemoryLimit();
            }
            
            $entry = $this->parser->parseLine(trim($line), $now, $cutoffDate);
            if ($entry !== null) {
                $this->processEntry($entry);
            }
        }
        
        $wrapper->close();
        
        if ($fileSizeMB > 10 && $this->config['verbose']) {
            echo " done" . PHP_EOL;
        }
        
        if ($this->config['verbose']) {
            $successRate = $this->processedLines > 0 ? ($this->parsedEntries / $this->processedLines * 100) : 0;
            printf(
                "Processing complete - Processed lines: %d, Parsed entries: %d, Success rate: %.2f%%\n",
                $this->processedLines, 
                $this->parsedEntries, 
                $successRate
            );
        }
    }

    private function openLogFile(string $filePath) {
        $realPath = realpath($filePath);
        if ($realPath === false) {
            throw new Exception("Failed to resolve file path: " . $filePath);
        }
        
        if (!$this->isSafePath($realPath)) {
            throw new SecurityError("Access to " . $realPath . " not allowed");
        }
        
        $fileSize = filesize($realPath);
        if ($fileSize === false) {
            throw new Exception("Failed to get file size: " . $realPath);
        }
        
        if (str_ends_with($realPath, ".gz")) {
            $handle = @gzopen($realPath, "r");
            if ($handle === false) {
                throw new Exception("Cannot open gzipped file: " . $realPath);
            }
            return new GzFileWrapper($handle);
        } elseif (str_ends_with($realPath, ".bz2")) {
            if ($fileSize > $this->config['max_file_size_mb'] * 1024 * 1024) {
                throw new SecurityError("Compressed file too large: " . $fileSize . " bytes");
            }
            $handle = @bzopen($realPath, "r");
            if ($handle === false) {
                throw new Exception("Cannot open bzipped file: " . $realPath);
            }
            return new BzFileWrapper($handle);
        } else {
            $handle = @fopen($realPath, "r");
            if ($handle === false) {
                throw new Exception("Cannot open file: " . $realPath);
            }
            return new FileWrapper($handle);
        }
    }

    private function isSafePath(string $path): bool {
        $realPath = realpath($path);
        if ($realPath === false) {
            return false;
        }
        
        $realPath = rtrim($realPath, '/');
        
        foreach (self::ALLOWED_DIRS as $allowed) {
            $allowed = rtrim($allowed, '/');
            if (str_starts_with($realPath, $allowed)) {
                $rel = substr($realPath, strlen($allowed));
                if ($rel === '' || $rel[0] === '/') {
                    $rel = ltrim($rel, '/');
                    $parts = explode('/', $rel);
                    foreach ($parts as $part) {
                        if ($part === '..' || $part === '.') {
                            return false;
                        }
                    }
                    return true;
                }
            }
        }
        return false;
    }

    private function checkMemoryLimit(): void {
        $memoryUsage = memory_get_usage(true);
        if ($memoryUsage > self::MEMORY_LIMIT_BYTES * 0.9) {
            if (!$this->memoryWarning) {
                echo "\nWarning: Approaching memory limit (" . round($memoryUsage / (1024 * 1024), 1) . "MB used)\n";
                $this->memoryWarning = true;
            }
        }
    }

    private function processEntry(LogEntry $entry): void {
        if ($this->storage->size() >= $this->config['max_memory_entries']) {
            if (!$this->memoryWarning) {
                echo "Memory limit reached: " . $this->config['max_memory_entries'] . " entries\n";
                $this->memoryWarning = true;
            }
            return;
        }
        
        $this->parsedEntries++;
        $dateKey = $entry->timestamp->format("Y-m-d");
        $this->tree->addEntry($dateKey, $entry->service, $entry);
        $this->storage->add($entry);
        
        if ($this->config['enable_analysis']) {
            $this->analysisResults->update($entry);
        }
        
        foreach ($this->plugins as $plugin) {
            $plugin->processEntry($entry);
        }
    }

    public function buildTree(): void {
        $tree = $this->tree->getTree();
        
        foreach ($tree as $date => $services) {
            foreach ($services as $service => $logs) {
                usort($logs, fn($a, $b) => $a->timestamp <=> $b->timestamp);
            }
        }
    }

    public function displaySystemInfo(): void {
        $rsyslogInfo = $this->parser->getRSyslogInfo();
        
        echo PHP_EOL . "=== System Information ===" . PHP_EOL;
        echo "Patterns loaded: " . $this->parser->getPatternCount() . PHP_EOL;
        
        if ($rsyslogInfo !== null) {
            echo "RSyslog detected: true" . PHP_EOL;
            echo "RSyslog version: " . $rsyslogInfo->version . PHP_EOL;
            echo "RainerScript bits: " . $rsyslogInfo->rainerscriptBits . PHP_EOL;
            
            $recommendations = $rsyslogInfo->getConfigRecommendations();
            if (!empty($recommendations)) {
                echo PHP_EOL . "Recommendations:" . PHP_EOL;
                foreach ($recommendations as $recommendation) {
                    echo "  • " . $recommendation . PHP_EOL;
                }
            }
        } else {
            echo "RSyslog detected: false" . PHP_EOL;
        }
    }

    public function displayTree(): void {
        $tree = $this->tree->getTree();
        
        if (empty($tree)) {
            echo "No logs to display." . PHP_EOL;
            return;
        }
        
        if ($this->config['color_output']) {
            echo PHP_EOL . "=== Syslog Analysis Tree ===" . PHP_EOL;
        } else {
            echo "Syslog Analysis Tree" . PHP_EOL;
            echo str_repeat("=", 50) . PHP_EOL;
        }
        
        $dates = $this->tree->getDates();
        sort($dates);
        
        foreach ($dates as $date) {
            echo PHP_EOL . $date . PHP_EOL;
            $services = $tree[$date] ?? [];
            
            $serviceNames = array_keys($services);
            sort($serviceNames);
            
            $serviceCount = count($serviceNames);
            foreach ($serviceNames as $i => $service) {
                $logs = $services[$service];
                $errorCount = 0;
                foreach ($logs as $log) {
                    if ($log->isError()) {
                        $errorCount++;
                    }
                }
                
                $serviceDisplay = $service;
                if ($errorCount > 0) {
                    $serviceDisplay .= " [errors: " . $errorCount . "]";
                }
                
                $connector = ($i === $serviceCount - 1) ? "└── " : "├── ";
                echo $connector . $serviceDisplay . PHP_EOL;
                $this->displayServiceLogs($logs, $i === $serviceCount - 1);
            }
        }
        echo PHP_EOL;
    }

    private function displayServiceLogs(array $logs, bool $isLastService): void {
        $displayedCount = min(count($logs), $this->config['max_lines_per_service']);
        
        for ($i = 0; $i < $displayedCount; $i++) {
            $log = $logs[$i];
            $isLastLog = $i === $displayedCount - 1;
            $prefix = $isLastService ? "    " : "│   ";
            $prefix .= $isLastLog ? "└── " : "├── ";
            
            $this->displayLogEntry($log, $prefix, $isLastLog);
        }
        
        if (count($logs) > $this->config['max_lines_per_service']) {
            $overflowCount = count($logs) - $this->config['max_lines_per_service'];
            $errorCount = 0;
            for ($i = $this->config['max_lines_per_service']; $i < count($logs); $i++) {
                if ($logs[$i]->isError()) {
                    $errorCount++;
                }
            }
            
            $overflowMsg = "... (" . $overflowCount . " more logs";
            if ($errorCount > 0) {
                $overflowMsg .= ", " . $errorCount . " errors";
            }
            $overflowMsg .= ")";
            
            $prefix = $isLastService ? "    " : "│   ";
            echo $prefix . "└── " . $overflowMsg . PHP_EOL;
        }
    }

    private function displayLogEntry(LogEntry $log, string $prefix, bool $isLast): void {
        $timestamp = $log->timestamp->format("H:i:s");
        $levelIndicator = $log->level !== "" ? "[" . $log->level . "] " : "";
        
        if ($this->config['show_full_lines']) {
            $messageLines = [$log->message];
            $truncation = "";
        } elseif ($this->config['wrap_lines']) {
            $wrapWidth = max(40, $this->config['truncate_length'] - strlen($prefix) - strlen($timestamp) - strlen($levelIndicator) - 3);
            $messageLines = $this->wrapText($log->message, $wrapWidth);
            $truncation = "";
        } else {
            if (strlen($log->message) > $this->config['truncate_length']) {
                $messageLines = [substr($log->message, 0, $this->config['truncate_length'])];
                $truncation = "...";
            } else {
                $messageLines = [$log->message];
                $truncation = "";
            }
        }
        
        $firstLine = $prefix . "[" . $timestamp . "] " . $levelIndicator . $messageLines[0] . $truncation;
        $this->printLine($firstLine, $this->getStyleForLog($log));
        
        if ($this->config['wrap_lines'] && count($messageLines) > 1) {
            $connector = $isLast ? "       " : "│      ";
            for ($i = 1; $i < count($messageLines); $i++) {
                echo "│   " . $connector . $messageLines[$i] . PHP_EOL;
            }
        }
    }

    private function wrapText(string $text, int $width): array {
        if (strlen($text) <= $width) {
            return [$text];
        }
        
        $lines = [];
        $currentLine = "";
        $words = preg_split('/\s+/', $text);
        
        if ($words === false) {
            return [$text];
        }
        
        foreach ($words as $word) {
            if (strlen($currentLine) + strlen($word) + 1 <= $width) {
                $currentLine .= ($currentLine !== "" ? " " : "") . $word;
            } else {
                if ($currentLine !== "") {
                    $lines[] = $currentLine;
                }
                $currentLine = $word;
            }
        }
        
        if ($currentLine !== "") {
            $lines[] = $currentLine;
        }
        
        return $lines;
    }

    private function getStyleForLog(LogEntry $log): string {
        $levelStyles = [
            "ERROR" => "\033[31m",
            "ERR" => "\033[31m",
            "FATAL" => "\033[1;31m",
            "WARN" => "\033[33m",
            "WARNING" => "\033[33m",
            "INFO" => "\033[32m",
            "DEBUG" => "\033[34m",
            "CRIT" => "\033[1;31m",
            "CRITICAL" => "\033[1;31m",
        ];
        
        if ($log->level !== "") {
            $upperLevel = strtoupper($log->level);
            if (isset($levelStyles[$upperLevel])) {
                return $levelStyles[$upperLevel];
            }
        }
        
        $errorIndicators = ["error", "failed", "failure", "exception", "critical"];
        $lowerMessage = strtolower($log->message);
        foreach ($errorIndicators as $indicator) {
            if (str_contains($lowerMessage, $indicator)) {
                return "\033[31m";
            }
        }
        
        return "\033[0m";
    }

    private function printLine(string $text, string $style): void {
        if ($this->config['color_output'] && $style !== "") {
            echo $style . $text . "\033[0m" . PHP_EOL;
        } else {
            echo $text . PHP_EOL;
        }
    }

    public function displaySummary(): void {
        if ($this->analysisResults->totalEntries === 0) {
            echo "No logs found." . PHP_EOL;
            return;
        }
        
        if ($this->config['color_output']) {
            $this->displayColorSummary();
        } else {
            $this->displayTextSummary();
        }
    }

    private function displayColorSummary(): void {
        echo PHP_EOL . "=== Log Analysis Summary ===" . PHP_EOL;
        echo "Total entries: " . $this->analysisResults->totalEntries . PHP_EOL;
        echo "Unique services: " . count($this->analysisResults->uniqueServices) . PHP_EOL;
        echo "Date range: " . $this->analysisResults->dateRange[0] . " to " . $this->analysisResults->dateRange[1] . PHP_EOL;
        echo "Days with logs: " . count($this->tree->getDates()) . PHP_EOL;
        echo "Error count: " . $this->analysisResults->errorCount . PHP_EOL;
        
        arsort($this->analysisResults->serviceCounts);
        $topServices = array_slice($this->analysisResults->serviceCounts, 0, self::MAX_TOP_SERVICES, true);
        $servicesStr = "";
        $first = true;
        foreach ($topServices as $service => $count) {
            if (!$first) $servicesStr .= ", ";
            $servicesStr .= $service . " (" . $count . ")";
            $first = false;
        }
        echo "Top services: " . $servicesStr . PHP_EOL;
        
        if (!empty($this->analysisResults->levelDistribution)) {
            echo PHP_EOL . "Log Level Distribution:" . PHP_EOL;
            arsort($this->analysisResults->levelDistribution);
            foreach ($this->analysisResults->levelDistribution as $level => $count) {
                echo "  " . $level . ": " . $count . PHP_EOL;
            }
        }
        
        foreach ($this->plugins as $plugin) {
            $results = $plugin->getResults();
            if (!empty($results)) {
                echo PHP_EOL . "Plugin: " . get_class($plugin) . PHP_EOL;
                foreach ($results as $k => $v) {
                    echo "  " . $k . ": " . json_encode($v) . PHP_EOL;
                }
            }
        }
    }

    private function displayTextSummary(): void {
        echo PHP_EOL . "Summary:" . PHP_EOL;
        echo "  Total entries: " . $this->analysisResults->totalEntries . PHP_EOL;
        echo "  Unique services: " . count($this->analysisResults->uniqueServices) . PHP_EOL;
        echo "  Date range: " . $this->analysisResults->dateRange[0] . " to " . $this->analysisResults->dateRange[1] . PHP_EOL;
        echo "  Days with logs: " . count($this->tree->getDates()) . PHP_EOL;
        echo "  Error count: " . $this->analysisResults->errorCount . PHP_EOL;
        
        arsort($this->analysisResults->serviceCounts);
        $topServices = array_slice($this->analysisResults->serviceCounts, 0, self::MAX_TOP_SERVICES, true);
        $servicesStr = "";
        $first = true;
        foreach ($topServices as $service => $count) {
            if (!$first) $servicesStr .= ", ";
            $servicesStr .= $service . " (" . $count . ")";
            $first = false;
        }
        echo "  Top services: " . $servicesStr . PHP_EOL;
        
        if (!empty($this->analysisResults->levelDistribution)) {
            echo "  Level distribution:" . PHP_EOL;
            foreach ($this->analysisResults->levelDistribution as $level => $count) {
                echo "    " . $level . ": " . $count . PHP_EOL;
            }
        }
    }

    public function findErrors(string $service = ""): array {
        $entries = $this->storage->getAll();
        $errors = [];
        
        foreach ($entries as $log) {
            if ($service !== "" && $log->service !== $service) {
                continue;
            }
            if ($log->isError()) {
                $errors[] = $log;
            }
        }
        
        usort($errors, fn($a, $b) => $a->timestamp <=> $b->timestamp);
        
        return $errors;
    }

    public function filterLogs(?string $servicePattern, ?string $level, ?string $messageContains): array {
        $entries = $this->storage->getAll();
        $filtered = [];
        
        $serviceRegex = null;
        if ($servicePattern !== null && $servicePattern !== "") {
            $pattern = '/^' . str_replace(['*', '.', '/', '-'], ['.*', '\.', '\/', '\-'], $servicePattern) . '$/';
            if (@preg_match($pattern, '') !== false) {
                $serviceRegex = $pattern;
            }
        }
        
        foreach ($entries as $log) {
            if ($serviceRegex !== null && !preg_match($serviceRegex, $log->service)) {
                continue;
            }
            if ($level !== null && $level !== "" && strtoupper($log->level) !== strtoupper($level)) {
                continue;
            }
            if ($messageContains !== null && $messageContains !== "" && !str_contains(strtolower($log->message), strtolower($messageContains))) {
                continue;
            }
            $filtered[] = $log;
        }
        
        usort($filtered, fn($a, $b) => $a->timestamp <=> $b->timestamp);
        
        return $filtered;
    }
}

function validateInput(array $options): array {
    $errors = [];
    
    if ($options["max-days"] < 1 || $options["max-days"] > 365) {
        $errors[] = "max-days must be between 1 and 365";
    }
    
    if ($options["truncate-length"] < 20 || $options["truncate-length"] > 1000) {
        $errors[] = "truncate-length must be between 20 and 1000";
    }
    
    if ($options["max-lines-per-service"] < 1 || $options["max-lines-per-service"] > 100) {
        $errors[] = "max-lines-per-service must be between 1 and 100";
    }
    
    if ($options["max-file-size"] < 1 || $options["max-file-size"] > 1000) {
        $errors[] = "max-file-size must be between 1 and 1000";
    }
    
    if ($options["max-memory-entries"] < 1000 || $options["max-memory-entries"] > 1000000) {
        $errors[] = "max-memory-entries must be between 1000 and 1000000";
    }
    
    if ($options["service"] !== "" && !preg_match('/^[a-zA-Z0-9\-_\/\.]+$/', $options["service"])) {
        $errors[] = "service contains invalid characters";
    }
    
    if ($options["filter-service"] !== "" && !preg_match('/^[a-zA-Z0-9\-_\/\.\*]+$/', $options["filter-service"])) {
        $errors[] = "filter-service contains invalid characters";
    }
    
    if ($options["filter-level"] !== "" && !preg_match('/^[a-zA-Z]+$/', $options["filter-level"])) {
        $errors[] = "filter-level contains invalid characters";
    }
    
    if (!empty($errors)) {
        throw new InvalidArgumentException(implode(", ", $errors));
    }
    
    return $options;
}

function main(array $argv): void {
    $options = [
        "log-file" => "",
        "max-days" => 30,
        "truncate-length" => 80,
        "show-full-lines" => false,
        "wrap-lines" => false,
        "max-lines-per-service" => 5,
        "no-color" => false,
        "verbose" => false,
        "summary" => false,
        "system-info" => false,
        "enable-analysis" => false,
        "find-errors" => false,
        "service" => "",
        "filter-service" => "",
        "filter-level" => "",
        "filter-message" => "",
        "max-file-size" => 100,
        "max-memory-entries" => 100000,
        "no-rsyslog-detection" => false,
        "version" => false,
        "help" => false,
    ];
    
    $args = [];
    for ($i = 1; $i < count($argv); $i++) {
        $arg = $argv[$i];
        if ($arg === "--help" || $arg === "-h") {
            $options["help"] = true;
            continue;
        }
        if ($arg === "--version" || $arg === "-v") {
            $options["version"] = true;
            continue;
        }
        if (str_starts_with($arg, "--")) {
            $argName = substr($arg, 2);
            if (str_contains($argName, "=")) {
                $parts = explode("=", $argName, 2);
                $key = $parts[0];
                $value = $parts[1];
                $args[$key] = $value;
            } else {
                $args[$argName] = true;
            }
        }
    }
    
    foreach ($args as $key => $value) {
        if (array_key_exists($key, $options)) {
            if (is_bool($options[$key])) {
                $options[$key] = filter_var($value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE) ?? false;
            } elseif (is_int($options[$key])) {
                $options[$key] = is_numeric($value) ? (int)$value : $options[$key];
            } else {
                $options[$key] = (string)$value;
            }
        }
    }
    
    if ($options["help"]) {
        echo "Usage: php rsyslog_analyzer.php [OPTIONS]\n";
        echo "Options:\n";
        echo "  --log-file=FILE          Specify log file to analyze\n";
        echo "  --max-days=DAYS          Analyze logs from last N days (default: 30)\n";
        echo "  --summary                Display summary statistics\n";
        echo "  --system-info            Display system and parser information\n";
        echo "  --find-errors            Find and display error logs\n";
        echo "  --service=SERVICE        Filter by specific service name\n";
        echo "  --filter-service=PATTERN Filter by service pattern (wildcards * allowed)\n";
        echo "  --filter-level=LEVEL     Filter by log level\n";
        echo "  --filter-message=TEXT    Filter by message content\n";
        echo "  --truncate-length=N      Truncate messages to N characters (default: 80)\n";
        echo "  --show-full-lines        Show full log messages without truncation\n";
        echo "  --wrap-lines             Wrap long messages across lines\n";
        echo "  --max-lines-per-service=N Maximum lines per service (default: 5)\n";
        echo "  --no-color               Disable colored output\n";
        echo "  --verbose                Enable verbose output\n";
        echo "  --max-file-size=MB       Maximum file size in MB (default: 100)\n";
        echo "  --max-memory-entries=N   Maximum log entries in memory (default: 100000)\n";
        echo "  --no-rsyslog-detection   Disable rsyslog detection\n";
        echo "  --version                Display version information\n";
        echo "  --help                   Display this help message\n";
        return;
    }
    
    if ($options["version"]) {
        echo "RSyslogAnalyzer 4.0.0 (PHP)\n";
        return;
    }
    
    try {
        $options = validateInput($options);
    } catch (InvalidArgumentException $e) {
        echo "Error: " . $e->getMessage() . PHP_EOL;
        exit(1);
    }
    
    $config = [
        'max_days' => $options["max-days"],
        'truncate_length' => $options["truncate-length"],
        'show_full_lines' => $options["show-full-lines"],
        'wrap_lines' => $options["wrap-lines"],
        'max_lines_per_service' => $options["max-lines-per-service"],
        'color_output' => !$options["no-color"],
        'verbose' => $options["verbose"],
        'enable_analysis' => $options["enable-analysis"] || $options["summary"] || $options["system-info"],
        'max_file_size_mb' => $options["max-file-size"],
        'max_memory_entries' => $options["max-memory-entries"],
        'use_rsyslog_detection' => !$options["no-rsyslog-detection"],
    ];
    
    try {
        $analyzer = new RSyslogAnalyzer($options["log-file"], $config);
        
        if ($options["system-info"]) {
            $analyzer->displaySystemInfo();
            return;
        }
        
        $analyzer->loadLogs();
        $analyzer->buildTree();
        
        if ($options["find-errors"]) {
            $errors = $analyzer->findErrors($options["service"]);
            if (!empty($errors)) {
                echo PHP_EOL . "Found " . count($errors) . " error logs:" . PHP_EOL;
                $displayCount = min(count($errors), 10);
                $start = max(0, count($errors) - $displayCount);
                for ($i = $start; $i < count($errors); $i++) {
                    $err = $errors[$i];
                    $message = $err->message;
                    if (strlen($message) > 100) {
                        $message = substr($message, 0, 100) . "...";
                    }
                    echo "  " . $err->timestamp->format("Y-m-d H:i:s") . " [" . $err->service . "] " . $message . PHP_EOL;
                }
            } else {
                echo "No error logs found." . PHP_EOL;
            }
        } elseif ($options["filter-service"] !== "" || $options["filter-level"] !== "" || $options["filter-message"] !== "") {
            $filtered = $analyzer->filterLogs($options["filter-service"], $options["filter-level"], $options["filter-message"]);
            if (!empty($filtered)) {
                echo PHP_EOL . "Found " . count($filtered) . " matching logs:" . PHP_EOL;
                $displayCount = min(count($filtered), 20);
                $start = max(0, count($filtered) - $displayCount);
                for ($i = $start; $i < count($filtered); $i++) {
                    $log = $filtered[$i];
                    $message = $log->message;
                    if (strlen($message) > 80) {
                        $message = substr($message, 0, 80) . "...";
                    }
                    $level = $log->level !== "" ? $log->level : "N/A";
                    echo "  " . $log->timestamp->format("Y-m-d H:i:s") . " [" . $log->service . "] " . $level . ": " . $message . PHP_EOL;
                }
            } else {
                echo "No matching logs found." . PHP_EOL;
            }
        } elseif ($options["summary"]) {
            $analyzer->displaySummary();
        } else {
            $analyzer->displayTree();
        }
    } catch (SecurityError $e) {
        echo "Security Error: " . $e->getMessage() . PHP_EOL;
        exit(1);
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . PHP_EOL;
        if ($config['verbose']) {
            echo $e->getTraceAsString() . PHP_EOL;
        }
        exit(1);
    }
}

if (php_sapi_name() === "cli") {
    main($argv);
}
