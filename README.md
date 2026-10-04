# Glitch Hound

Glitch Hound is a Windows desktop application that helps users audit websites
and servers, understand common security findings, and track remediation. It
combines a graphical interface with defensive scanning tools and plain-language
explanations.

> **Use responsibly:** Only scan websites, servers, and networks that you own
> or are explicitly authorized to assess. Glitch Hound is intended for
> defensive auditing and education; it does not exploit vulnerabilities.

## Features

- Website security checks for TLS certificates, HTTP security headers, cookie
  flags, exposed paths, directory listings, and server information.
- Network reconnaissance, including host resolution, TCP port checks, and
  service/banner identification.
- Email-domain trust checks for SPF and DMARC DNS records.
- External-script inventory to help identify third-party dependencies.
- Explainable risk summaries and a visual “digital house” representation of
  findings.
- Suggested remediation snippets and downloadable scan reports (PDF, CSV, and
  JSON).
- Account registration, email OTP verification, password reset, scan history,
  and admin tools.
- Mock payments for local demos, with optional Razorpay hosted checkout.

## Requirements

- Windows 10 or later
- Python 3.10 or later
- MongoDB database (MongoDB Atlas works)
- Network access for database connectivity and online scanning features

## Getting started

Open PowerShell in the project directory:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` and replace the example values with your own configuration. At a
minimum, set `MONGODB_URI` to a MongoDB connection string and `DB_NAME` to the
database name you want to use. Do not commit `.env` or share it publicly.

For local development and demos, keep the payment mode set to `mock`. To use
Razorpay instead, configure `RAZORPAY_KEY_ID` and `RAZORPAY_KEY_SECRET`, set
`PAYMENT_GATEWAY_MODE=razorpay`, and install its optional package:

```powershell
pip install razorpay
```

Start the application:

```powershell
python main.py
```

## Configuration

| Variable | Purpose |
| --- | --- |
| `MONGODB_URI` | MongoDB connection string |
| `DB_NAME` | MongoDB database name |
| `PAYMENT_GATEWAY_MODE` | `mock` (default) or `razorpay` |
| `RAZORPAY_KEY_ID` | Razorpay API key ID; needed only in Razorpay mode |
| `RAZORPAY_KEY_SECRET` | Razorpay API secret; needed only in Razorpay mode |
| `ADMIN_USERNAME` | Username for the predefined admin account |
| `ADMIN_EMAIL` | Email for the predefined admin account |
| `ADMIN_PASSWORD` | Set a strong password to seed the admin account |
| `SMTP_HOST`, `SMTP_PORT` | SMTP server settings for email OTP delivery |
| `SMTP_USER`, `SMTP_PASSWORD` | SMTP authentication credentials |
| `SMTP_FROM_EMAIL` | Sender address for verification emails |
| `OTP_EXPIRY_MINUTES` | OTP validity period |
| `OTP_MAX_ATTEMPTS` | Maximum OTP verification attempts |
| `OTP_PEPPER` | Optional secret used in OTP handling; set a private value |

If SMTP credentials are not configured, OTPs are printed to the application
console for development. Configure SMTP before using email verification in a
real deployment.

## Run tests

The test suite uses Python's built-in `unittest` framework:

```powershell
python -m unittest discover -s tests
```

## Build a Windows executable

Install PyInstaller, then run the included build script:

```powershell
pip install pyinstaller
.\build.bat
```

Alternatively, run `pyinstaller glitchhound.spec --clean`. Build and
distribution notes are in [BUILD.md](BUILD.md). Keep secrets out of a
distributed executable; provide configuration securely for each installation.

## Project structure

| Directory/file | Purpose |
| --- | --- |
| `gui/` | Desktop interface and application navigation |
| `scanner/` | Website, network, email, and risk-analysis tools |
| `auth/` | Registration, login, OTP, and password handling |
| `database/` | MongoDB access and persisted application data |
| `payment/` | Mock and Razorpay payment integrations |
| `utils/` | Reporting and shared utilities |
| `config.py` | Application configuration and subscription plans |
| `main.py` | Application entry point |

## License

No license file is currently included in this repository. Contact the
repository owner for permission and licensing information before redistributing
or reusing the project.
