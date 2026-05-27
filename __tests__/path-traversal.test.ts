import * as fs from 'fs'
import * as path from 'path'
import {getConfigFileContent} from '../src/main'

describe('path traversal vulnerability tests', () => {
  const testDir = path.join(__dirname, 'test-configs')
  const validConfigFile = path.join(testDir, 'valid-config.yml')
  const relativeConfigPath = 'valid-config.yml'

  beforeAll(() => {
    // Create test directory and files
    if (!fs.existsSync(testDir)) {
      fs.mkdirSync(testDir, {recursive: true})
    }
    fs.writeFileSync(validConfigFile, 'test:\n  - "**/*.js"\n', 'utf8')
  })

  afterAll(() => {
    // Clean up test files
    if (fs.existsSync(validConfigFile)) {
      fs.unlinkSync(validConfigFile)
    }
    if (fs.existsSync(testDir)) {
      fs.rmdirSync(testDir)
    }
  })

  describe('security: path traversal prevention', () => {
    test('rejects path with parent directory traversal (..)', () => {
      const maliciousPath = '../../../etc/passwd'
      expect(() => getConfigFileContent(maliciousPath)).toThrow('Invalid configuration file path')
    })

    test('rejects path with encoded parent directory traversal', () => {
      const maliciousPath = '..%2F..%2F..%2Fetc%2Fpasswd'
      expect(() => getConfigFileContent(maliciousPath)).toThrow('Invalid configuration file path')
    })

    test('rejects path with mixed traversal patterns', () => {
      const maliciousPath = 'config/../../../etc/passwd'
      expect(() => getConfigFileContent(maliciousPath)).toThrow('Invalid configuration file path')
    })

    test('rejects absolute Unix path', () => {
      const maliciousPath = '/etc/passwd'
      expect(() => getConfigFileContent(maliciousPath)).toThrow('Invalid configuration file path')
    })

    test('rejects absolute Windows path on Windows or when detected', () => {
      const maliciousPath = 'C:\\Windows\\System32\\config\\SAM'
      // On Windows, path.isAbsolute will catch this
      // On Unix, it won't be recognized as absolute but the file won't exist anyway
      if (path.isAbsolute(maliciousPath)) {
        expect(() => getConfigFileContent(maliciousPath)).toThrow('Invalid configuration file path')
      } else {
        // On Unix systems, this is treated as a relative path and will fail with file not found
        expect(() => getConfigFileContent(maliciousPath)).toThrow()
      }
    })

    test('rejects UNC path on Windows or when detected', () => {
      const maliciousPath = '\\\\server\\share\\file'
      // On Windows, path.isAbsolute will catch this
      // On Unix, it won't be recognized as absolute but the file won't exist anyway
      if (path.isAbsolute(maliciousPath)) {
        expect(() => getConfigFileContent(maliciousPath)).toThrow('Invalid configuration file path')
      } else {
        // On Unix systems, this is treated as a relative path and will fail with file not found
        expect(() => getConfigFileContent(maliciousPath)).toThrow()
      }
    })
  })

  describe('valid relative paths', () => {
    test('accepts simple relative path', () => {
      // Change to test directory to make relative path work
      const originalCwd = process.cwd()
      try {
        process.chdir(testDir)
        const content = getConfigFileContent(relativeConfigPath)
        expect(content).toContain('test:')
      } finally {
        process.chdir(originalCwd)
      }
    })

    test('accepts relative path with subdirectory', () => {
      const subDir = path.join(testDir, 'subdir')
      const subConfigFile = path.join(subDir, 'config.yml')
      
      if (!fs.existsSync(subDir)) {
        fs.mkdirSync(subDir, {recursive: true})
      }
      fs.writeFileSync(subConfigFile, 'test:\n  - "**/*.ts"\n', 'utf8')

      const originalCwd = process.cwd()
      try {
        process.chdir(testDir)
        const content = getConfigFileContent('subdir/config.yml')
        expect(content).toContain('test:')
      } finally {
        process.chdir(originalCwd)
        if (fs.existsSync(subConfigFile)) {
          fs.unlinkSync(subConfigFile)
        }
        if (fs.existsSync(subDir)) {
          fs.rmdirSync(subDir)
        }
      }
    })
  })

  describe('error handling for non-existent and invalid files', () => {
    test('throws error for non-existent file', () => {
      expect(() => getConfigFileContent('non-existent-file.yml')).toThrow(
        "Configuration file 'non-existent-file.yml' not found"
      )
    })

    test('throws error when path points to directory', () => {
      const originalCwd = process.cwd()
      try {
        process.chdir(__dirname)
        expect(() => getConfigFileContent('test-configs')).toThrow("'test-configs' is not a file.")
      } finally {
        process.chdir(originalCwd)
      }
    })
  })
})
