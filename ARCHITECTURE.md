# Architecture — Password Strength & Breach Checker

## 1. System Overview

This project is a web-based password security tool that evaluates password strength, checks password breach exposure using the Have I Been Pwned Pwned Passwords API, supports email breach lookup when authenticated HIBP access is available, and generates secure passwords.

## 2. Architecture

```text
User
 |
 +--------------------+
 |                    |
 v                    v
Password Input      Email Input
 |                    |
 v                    v
zxcvbn Analysis     HIBP API
 |                    |
 |                    v
 |               Breach Result
 |
 v
Strength Score
 |
 v
SHA-1 Hash
 |
 v
First 5 Hash Characters
 |
 v
HIBP Pwned Passwords API
 |
 v
Local Hash Suffix Matching
 |
 v
Breach Count