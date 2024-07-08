# 2FA Authentication API

## Overview

This API provides secure two-factor authentication (2FA) functionality using Django REST Framework. It enhances user account security by requiring a second form of verification alongside passwords.

### Features

- **OTP Generation:** Uses `pyotp` library for generating time-based one-time passwords (TOTP).
- **QR Code Integration:** Allows users to set up 2FA by scanning QR codes with apps like Google Authenticator.

## Installation

1. Clone the repository.
2. Install dependencies using `pip install -r requirements.txt`.
3. Configure settings and database.
4. Run migrations with `python manage.py migrate`.

## Usage

- **Endpoints:**
  - `/login`: POST request to authenticate and obtain tokens as first time login.
  - `/enable_2fa`: POST request to enable 2FA for a user.
  - `/verify_otp`: POST request to verify OTP after enable 2FA.
  - `/get_qr_code`: GET request to retrieve QR code.

- **Authentication:**
  - JWT tokens are used for authentication. Include `Authorization: Bearer <token>` header in requests.

