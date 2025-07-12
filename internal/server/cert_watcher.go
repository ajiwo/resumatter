package server

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"resumatter/internal/errors"
)

// CertWatcher watches certificate files for changes and triggers reloads
type CertWatcher struct {
	mu sync.RWMutex

	// File paths to watch
	certFile string
	keyFile  string
	caFile   string

	// File metadata
	lastModTime map[string]time.Time

	// Watcher components
	fsWatcher     *fsnotify.Watcher
	debounceDelay time.Duration
	debounceTimer *time.Timer

	// Control channels
	stopChan   chan struct{}
	reloadChan chan struct{}

	// Callback and logging
	reloadCallback func()
	logger         *errors.Logger

	// State
	running bool
}

// NewCertWatcher creates a new certificate file watcher
func NewCertWatcher(certFile, keyFile, caFile string, debounceDelay time.Duration, reloadCallback func(), logger *errors.Logger) (*CertWatcher, error) {
	if debounceDelay == 0 {
		debounceDelay = time.Second // Default 1 second debounce
	}

	return &CertWatcher{
		certFile:       certFile,
		keyFile:        keyFile,
		caFile:         caFile,
		lastModTime:    make(map[string]time.Time),
		debounceDelay:  debounceDelay,
		stopChan:       make(chan struct{}),
		reloadChan:     make(chan struct{}, 1), // Buffered to prevent blocking
		reloadCallback: reloadCallback,
		logger:         logger,
	}, nil
}

// Start begins watching certificate files for changes
func (cw *CertWatcher) Start() error {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	if cw.running {
		return fmt.Errorf("certificate watcher is already running")
	}

	if err := cw.initializeWatcher(); err != nil {
		return err
	}

	filesToWatch := cw.collectFilesToWatch()
	cw.addFilesToWatcher(filesToWatch)

	cw.running = true
	go cw.watchLoop()

	cw.logWatcherStarted(filesToWatch)
	return nil
}

// initializeWatcher creates and initializes the file system watcher
func (cw *CertWatcher) initializeWatcher() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}
	cw.fsWatcher = watcher

	if err := cw.updateModTimes(); err != nil {
		cw.cleanupWatcher()
		return fmt.Errorf("failed to get initial file modification times: %w", err)
	}

	return nil
}

// cleanupWatcher closes the file watcher and logs any errors
func (cw *CertWatcher) cleanupWatcher() {
	if cw.fsWatcher != nil {
		if closeErr := cw.fsWatcher.Close(); closeErr != nil && cw.logger != nil {
			cw.logger.LogError(closeErr, "Failed to close file watcher during cleanup")
		}
	}
}

// collectFilesToWatch gathers all certificate files that need to be watched
func (cw *CertWatcher) collectFilesToWatch() []string {
	var filesToWatch []string

	if cw.certFile != "" {
		filesToWatch = append(filesToWatch, cw.certFile)
	}
	if cw.keyFile != "" {
		filesToWatch = append(filesToWatch, cw.keyFile)
	}
	if cw.caFile != "" {
		filesToWatch = append(filesToWatch, cw.caFile)
	}

	return filesToWatch
}

// addFilesToWatcher adds all files to the file system watcher
func (cw *CertWatcher) addFilesToWatcher(filesToWatch []string) {
	for _, file := range filesToWatch {
		if err := cw.addFileToWatcher(file); err != nil && cw.logger != nil {
			cw.logger.Warn("Failed to watch certificate file", "file", file, "error", err)
		}
	}
}

// logWatcherStarted logs that the watcher has been started
func (cw *CertWatcher) logWatcherStarted(filesToWatch []string) {
	if cw.logger != nil {
		cw.logger.Info("Certificate file watcher started",
			"files", filesToWatch,
			"debounce_delay", cw.debounceDelay)
	}
}

// Stop stops the certificate file watcher
func (cw *CertWatcher) Stop() error {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	if !cw.running {
		return nil
	}

	// Signal stop
	close(cw.stopChan)

	// Stop debounce timer if running
	if cw.debounceTimer != nil {
		cw.debounceTimer.Stop()
	}

	// Close file system watcher
	if cw.fsWatcher != nil {
		if err := cw.fsWatcher.Close(); err != nil {
			if cw.logger != nil {
				cw.logger.LogError(err, "Failed to close file system watcher")
			}
			return err
		}
	}

	cw.running = false

	if cw.logger != nil {
		cw.logger.Info("Certificate file watcher stopped")
	}

	return nil
}

// addFileToWatcher adds a file and its directory to the file system watcher
func (cw *CertWatcher) addFileToWatcher(file string) error {
	// Watch the file itself
	if err := cw.fsWatcher.Add(file); err != nil {
		// If the file doesn't exist, watch its directory instead
		if os.IsNotExist(err) {
			dir := filepath.Dir(file)
			if err := cw.fsWatcher.Add(dir); err != nil {
				return fmt.Errorf("failed to watch directory %s: %w", dir, err)
			}
			if cw.logger != nil {
				cw.logger.Info("Watching directory for certificate file",
					"file", file, "directory", dir)
			}
		} else {
			return fmt.Errorf("failed to watch file %s: %w", file, err)
		}
	}

	// Also watch the directory to catch atomic writes (rename operations)
	dir := filepath.Dir(file)
	if err := cw.fsWatcher.Add(dir); err != nil {
		if cw.logger != nil {
			cw.logger.Warn("Failed to watch directory for atomic writes",
				"directory", dir, "error", err)
		}
	}

	return nil
}

// updateModTimes updates the stored modification times for all watched files
func (cw *CertWatcher) updateModTimes() error {
	files := []string{}
	if cw.certFile != "" {
		files = append(files, cw.certFile)
	}
	if cw.keyFile != "" {
		files = append(files, cw.keyFile)
	}
	if cw.caFile != "" {
		files = append(files, cw.caFile)
	}

	for _, file := range files {
		if stat, err := os.Stat(file); err == nil {
			cw.lastModTime[file] = stat.ModTime()
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("failed to stat file %s: %w", file, err)
		}
	}

	return nil
}

// hasFileChanged checks if a file has been modified since last check
func (cw *CertWatcher) hasFileChanged(file string) bool {
	stat, err := os.Stat(file)
	if err != nil {
		if os.IsNotExist(err) {
			// File was deleted
			if _, exists := cw.lastModTime[file]; exists {
				delete(cw.lastModTime, file)
				return true
			}
		}
		return false
	}

	lastMod, exists := cw.lastModTime[file]
	if !exists || stat.ModTime().After(lastMod) {
		cw.lastModTime[file] = stat.ModTime()
		return true
	}

	return false
}

// watchLoop is the main event loop for file watching
func (cw *CertWatcher) watchLoop() {
	for {
		select {
		case event, ok := <-cw.fsWatcher.Events:
			if !ok {
				return
			}

			if cw.shouldProcessEvent(event) {
				cw.scheduleReload()
			}

		case err, ok := <-cw.fsWatcher.Errors:
			if !ok {
				return
			}
			if cw.logger != nil {
				cw.logger.LogError(err, "File watcher error")
			}

		case <-cw.reloadChan:
			// Debounced reload trigger
			if cw.hasAnyFileChanged() {
				if cw.logger != nil {
					cw.logger.Info("Certificate files changed, triggering reload")
				}
				cw.reloadCallback()
			}

		case <-cw.stopChan:
			return
		}
	}
}

// shouldProcessEvent determines if a file system event should trigger a reload check
func (cw *CertWatcher) shouldProcessEvent(event fsnotify.Event) bool {
	// Check if the event is for one of our watched files
	watchedFiles := []string{cw.certFile, cw.keyFile, cw.caFile}
	isWatchedFile := false

	for _, file := range watchedFiles {
		if file != "" && (event.Name == file || filepath.Base(event.Name) == filepath.Base(file)) {
			isWatchedFile = true
			break
		}
	}

	if !isWatchedFile {
		return false
	}

	// Process write, create, and rename events
	return event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0
}

// hasAnyFileChanged checks if any of the watched files have changed
func (cw *CertWatcher) hasAnyFileChanged() bool {
	files := []string{}
	if cw.certFile != "" {
		files = append(files, cw.certFile)
	}
	if cw.keyFile != "" {
		files = append(files, cw.keyFile)
	}
	if cw.caFile != "" {
		files = append(files, cw.caFile)
	}

	return slices.ContainsFunc(files, cw.hasFileChanged)
}

// scheduleReload schedules a debounced reload
func (cw *CertWatcher) scheduleReload() {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	// Reset the debounce timer
	if cw.debounceTimer != nil {
		cw.debounceTimer.Stop()
	}

	cw.debounceTimer = time.AfterFunc(cw.debounceDelay, func() {
		select {
		case cw.reloadChan <- struct{}{}:
			// Reload scheduled
		default:
			// Channel is full, reload already scheduled
		}
	})
}

// IsRunning returns whether the watcher is currently running
func (cw *CertWatcher) IsRunning() bool {
	cw.mu.RLock()
	defer cw.mu.RUnlock()
	return cw.running
}

// GetWatchedFiles returns the list of files being watched
func (cw *CertWatcher) GetWatchedFiles() []string {
	files := []string{}
	if cw.certFile != "" {
		files = append(files, cw.certFile)
	}
	if cw.keyFile != "" {
		files = append(files, cw.keyFile)
	}
	if cw.caFile != "" {
		files = append(files, cw.caFile)
	}
	return files
}
