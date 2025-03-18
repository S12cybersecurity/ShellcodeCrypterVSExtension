# ShellcodeCrypterVSExtension

A Visual Studio extension that provides a simple yet powerful interface for encrypting shellcode using XOR and AES encryption methods.

![image](https://github.com/user-attachments/assets/c8162261-26f7-49a3-b362-843f8ee77afd)


## Features

Encrypt shellcode using XOR or AES encryption algorithms

User-friendly interface integrated directly into Visual Studio

Customizable encryption keys

Display results in both hexadecimal and plain text formats

Dark theme compatible to match the Visual Studio environment

## Installation
From Visual Studio Marketplace

Open Visual Studio

Go to Extensions > Manage Extensions

Search for "ShellcodeEncryptionVSExtension"

Or: [https://marketplace.visualstudio.com/items?itemName=0x12DarkDevelopment.shellcodeEncryption](https://marketplace.visualstudio.com/items?itemName=0x12DarkDevelopment.shellcodeEncryption)

Click Download and follow the installation instructions

Restart Visual Studio when prompted

## Manual Installation

Download the latest VSIX file from the Releases page

Close all Visual Studio instances

Double-click the downloaded VSIX file

Follow the installation prompts

Restart Visual Studio

## Usage

In Visual Studio, go to View > Other Windows > Shellcode Encryption Tool

Enter your shellcode in hexadecimal format (e.g., \x31\xc0\x50\x68)

Enter an encryption key

Select the encryption method (XOR or AES)

Click the "Encrypt" button

View the encrypted shellcode in both plain text and hexadecimal formats

## Supported Formats
Input shellcode can be provided in the following formats:

\x31\xc0\x50\x68
31 c0 50 68
31c05068

The extension will automatically clean the input and process it correctly.
Encryption Methods

XOR Encryption

XOR encryption is a simple but effective method that applies the XOR operation between the shellcode bytes and the key bytes. The key is used cyclically if it's shorter than the shellcode.

AES Encryption

AES (Advanced Encryption Standard) provides stronger encryption for your shellcode:

Uses industry-standard CBC mode with PKCS7 padding

Automatically adjusts key sizes to valid AES key lengths (16, 24, or 32 bytes)

Generates a random Initialization Vector (IV) for each encryption

IV is prepended to the encrypted data for later decryption

## Development
Prerequisites

Visual Studio 2019 or newer

.NET Framework 4.7.2 or newer

Visual Studio SDK

## Building from Source

Clone the repository:

```bash
git clone https://github.com/S12cybersecurity/ShellcodeCrypterVSExtension
```
Open the solution in Visual Studio

Restore NuGet packages

Build the solution

## Project Structure

ShellcodeEncryptionVSExtension: Main project containing the extension functionality

ToolWindowCommand.cs: Handles the tool window registration and display

ToolWindowControl.xaml: XAML UI definition

ToolWindowControl.xaml.cs: Code-behind file with encryption logic

