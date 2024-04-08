#﻿Ghost messenger  online version found at https://ghostmessenger.site
This is a big FU to The Assistance and Access Act in Australia, which allows law enforcement and security agencies to seek assistance from the full scope of companies that supply communications services and devices in Australia.

This secure Messaging App is a Flask-based web application that allows users to send encrypted messages securely. Without user accounts and with any username you choose. Utilizing RSA encryption, messages between senders and receivers are encrypted and decrypted, ensuring that only the intended recipient can read the message content. Messages are deleted once read.

Features
RSA Encryption for secure messaging.
Flask-WTF for form handling and CSRF protection.
Flask-Limiter for request rate limiting.
Flask-SQLAlchemy for database integration.

Prerequisites
Before you begin, ensure you have met the following requirements:

Python 3.6+
Pip (Python package manager)
A PostgreSQL database with a table named messages, heres how to create it

CREATE TABLE messages (
    id SERIAL PRIMARY KEY,
    message TEXT NOT NULL,
    sender_username VARCHAR(255) NOT NULL,
    receiver_username VARCHAR(255) NOT NULL,
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL
);



Installation
Follow these steps to install Secure Messaging App:

Clone the repository:
git clone https://github.com/ebbsy60/ghost.git
cd ghost

Set up a virtual environment (optional but recommended):
python3 -m venv venv

Activate the virtual enviroment with
source venv/bin/activate  
On Windows use 
venv\Scripts\activate

Install the required packages:
pip install -r requirements.txt


Set environment variables:
edit the .env file in the root directory of the project and populate it with the necessary environment variables:

SECRET_KEY=your_secret_key
DATABASE_URL=postgresql://username:password@localhost/dbname

Replace your_secret_key with a secure secret key, and postgresql://username:password@localhost/dbname with your PostgreSQL database URL.

to run open a terminal and type python app.py

