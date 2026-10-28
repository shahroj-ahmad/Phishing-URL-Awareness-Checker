# Screenshots Directory

This folder is reserved for genuine terminal screenshots of the application run and test execution.

---

## Required Screenshot Files

1. **`sample_run.png`**: Visual proof of running `python3 phishing_checker.py` and analyzing URLs with warnings.
2. **`test_results.png`**: Visual proof of executing `python3 -m unittest discover -s tests -v` with all 16 tests passing (`OK`).

---

## macOS Instructions for Capturing Genuine Screenshots

To ensure academic and project integrity, follow these quick steps on macOS:

### 1. Capture `sample_run.png`
1. Open **Terminal** or **VS Code Integrated Terminal**.
2. Run the interactive application:
   ```bash
   python3 phishing_checker.py
   ```
3. Enter 2 to 3 sample URLs (for example, `http://192.0.2.10`, `https://example.com`, and `https://mybank.com@example.invalid`).
4. Press `Cmd + Shift + 4` on your Mac keyboard.
5. Hit `Space` to turn the crosshair into a camera icon.
6. Click directly on your Terminal window to capture a window screenshot with shadow.
7. Locate the captured screenshot on your Desktop (or wherever macOS saves default captures).
8. Rename the file to `sample_run.png` and move it into this `screenshots/` directory:
   ```bash
   mv ~/Desktop/Screenshot*.png screenshots/sample_run.png
   ```

### 2. Capture `test_results.png`
1. In the same terminal, run the automated test suite:
   ```bash
   python3 -m unittest discover -s tests -v
   ```
2. Press `Cmd + Shift + 4`, then hit `Space`.
3. Click on the Terminal window showing the 16 tests passing and the `OK` status line.
4. Rename the saved file to `test_results.png` and move it into this `screenshots/` directory:
   ```bash
   mv ~/Desktop/Screenshot*.png screenshots/test_results.png
   ```
