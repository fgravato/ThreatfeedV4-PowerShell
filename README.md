# Improved Threat Feed Management System (PowerShell Version)

This system allows you to manage threat feeds using the Lookout API. It provides a user-friendly interface for creating, viewing, updating, and deleting threat feeds, as well as managing the domains within those feeds.

## Features

- Create new threat feeds
- List existing threat feeds
- View feed details
- Update feed content from online sources
- Delete threat feeds
- Add and remove domains from feeds
- User-friendly command-line interface
- Enhanced error handling and logging
- Input validation for user inputs

## Prerequisites

- PowerShell 5.1 or later

## Installation

1. Clone or download this repository to your local machine.

2. Create an `api_key.txt` file in the root directory of the project and paste your Lookout API key into it:

   ```powershell
   Set-Content -Path "api_key.txt" -Value "your-api-key-here"
   ```

## Usage

To run the Threat Feed Management System, execute the following command in your PowerShell terminal:

```powershell
.\Improved_Threat_Feed_Management.ps1
```

The system will present you with a menu-driven interface. Here are the main options:

1. View and Manage Existing Feeds
2. Create a New Threat Feed
3. Exit

## Enhancements

1. **PowerShell compatibility**: Converted from Python to PowerShell for better integration with Windows environments.
2. **Enhanced error handling**: Improved error messages and logging throughout the script.
3. **Input validation**: Added more rigorous input validation for user inputs.
4. **Confirmation prompts**: Added for critical actions like deleting feeds.
5. **Improved API connection test**: Now uses the `Get-FeedGuids` function to test the API connection at startup.

## Troubleshooting

If you encounter any issues:

1. Ensure your API key is correct and properly saved in the `api_key.txt` file.
2. Check your internet connection, as the script needs to communicate with the Lookout API.
3. Verify that you have PowerShell 5.1 or later installed.
4. Make sure you have the necessary permissions to execute PowerShell scripts on your system.
5. If you encounter API-related errors, check the script's output for more detailed error messages.

## Contributing

Contributions to improve the Threat Feed Management System are welcome. Please feel free to submit pull requests or open issues to discuss proposed changes or report bugs.

## Author

Frank Gravato (Lookout-SE)

