# Email Validator

A comprehensive web-based email validation tool that verifies email addresses in bulk using CSV upload. The validator performs format validation, MX record checking, SMTP verification, and provides detailed analytics matching the apilayer API format.

## Features

- ✅ **Format Validation** - Validates email syntax
- ✅ **MX Record Check** - Verifies domain has mail exchange records
- ✅ **SMTP Verification** - Checks if mailbox exists and can receive emails
- ✅ **Disposable Email Detection** - Identifies temporary/disposable email addresses
- ✅ **Role-based Email Detection** - Detects role-based emails (admin, info, support, etc.)
- ✅ **Free Email Provider Detection** - Identifies free email providers
- ✅ **Typo Suggestions** - Suggests corrections for common typos
- ✅ **Bulk Processing** - Upload and validate multiple emails via CSV
- ✅ **Real-time Progress** - Track validation progress in real-time
- ✅ **Analytics Dashboard** - View validation statistics and results
- ✅ **Export Results** - Download filtered results (valid/invalid/risky)

## Prerequisites

- Node.js (v14 or higher)
- npm (Node Package Manager)

## Installation

1. Clone or download the project
2. Navigate to the project directory:
   ```bash
   cd Email-validator
   ```

3. Install dependencies:
   ```bash
   npm install
   ```

## Running the Project

### Development Mode (with auto-reload)

```bash
npm run dev
```

This uses `nodemon` to automatically restart the server when files change.

### Production Mode

```bash
npm start
```

Or directly:

```bash
node server.js
```

The server will start on port 3000 by default. You can change the port by setting the `PORT` environment variable:

```bash
PORT=8080 npm start
```

## Accessing the Application

Once the server is running, open your web browser and navigate to:

```
http://localhost:3000
```

## API Endpoints

### 1. Upload CSV File for Validation

**POST** `/api/verify`

Upload a CSV file containing email addresses for validation.

- **Content-Type**: `multipart/form-data`
- **Field name**: `file`
- **Response**: Returns a `jobId` for tracking progress

**Example using curl:**
```bash
curl -X POST http://localhost:3000/api/verify \
  -F "file=@emails.csv"
```

**Example using JavaScript (fetch):**
```javascript
const formData = new FormData();
formData.append('file', fileInput.files[0]);

fetch('http://localhost:3000/api/verify', {
  method: 'POST',
  body: formData
})
.then(response => response.json())
.then(data => {
  console.log('Job ID:', data.jobId);
});
```

### 2. Get Job Progress

**GET** `/api/progress/:jobId`

Get the current progress of a validation job.

**Response:**
```json
{
  "progress": 75,
  "row": 75,
  "total": 100,
  "status": "processing"
}
```

### 3. Get Analytics

**GET** `/api/analytics/:jobId`

Get validation statistics for a completed job.

**Response:**
```json
{
  "total": 100,
  "valid": 65,
  "invalid": 30,
  "risky": 5,
  "validPercent": 65,
  "invalidPercent": 30,
  "riskyPercent": 5
}
```

### 4. Download Results

**GET** `/api/download/:jobId?type=all|valid|invalid|risky`

Download validation results as CSV.

**Query Parameters:**
- `type`: Filter type - `all`, `valid`, `invalid`, or `risky` (default: `all`)

**Example:**
```
http://localhost:3000/api/download/abc123?type=valid
```

### 5. Cancel Job

**POST** `/api/cancel/:jobId`

Cancel a running validation job.

## CSV File Format

The CSV file can have one of the following formats:

1. **Simple format** (one email per line):
   ```
   email@example.com
   another@example.com
   ```

2. **CSV with header**:
   ```csv
   email,name
   email@example.com,John Doe
   another@example.com,Jane Smith
   ```

3. **CSV without header** (first column is treated as email):
   ```csv
   email@example.com,John Doe
   another@example.com,Jane Smith
   ```

The validator will automatically detect the format and extract email addresses from a column named "email" (case-insensitive) or use the first column.

## Validation Response Format

Each email validation returns results in the following format (matching apilayer API):

```json
{
  "email": "user@example.com",
  "did_you_mean": "",
  "user": "user",
  "domain": "example.com",
  "format_valid": true,
  "mx_found": true,
  "smtp_check": true,
  "catch_all": null,
  "role": false,
  "disposable": false,
  "free": false,
  "score": 0.8,
  "status": "valid",
  "reason": "smtp_ok"
}
```

### Field Descriptions

- **email**: The email address being validated
- **did_you_mean**: Suggested correction if typo detected
- **user**: Local part of the email (before @)
- **domain**: Domain part of the email (after @)
- **format_valid**: Whether email format is valid
- **mx_found**: Whether domain has MX records
- **smtp_check**: Whether mailbox exists and can receive emails
- **catch_all**: Whether domain accepts all emails (null if not checked)
- **role**: Whether email is role-based (admin, info, etc.)
- **disposable**: Whether email is from a disposable provider
- **free**: Whether email is from a free provider
- **score**: Confidence score (0.0 to 0.8)
- **status**: Overall status - `valid`, `invalid`, or `risky`
- **reason**: Reason for the status

### Status Values

- **valid**: Email is deliverable (smtp_check: true)
- **invalid**: Email cannot receive emails (bad format, no MX, disposable, or smtp_check: false)
- **risky**: Uncertain deliverability (typo suggestions, low confidence)

## How It Works

1. **Format Validation**: Uses `email-validator` to check email syntax
2. **MX Record Check**: Queries DNS for Mail Exchange records
3. **SMTP Verification**: 
   - Primary: Uses `email-deep-validator` library (60s timeout)
   - Fallback: Direct SMTP connection to MX server
   - Handles providers that block verification (Gmail, Google Workspace, Outlook)
4. **Disposable Detection**: Checks against database of disposable email providers
5. **Typo Detection**: Uses `mailcheck` library to suggest corrections

## Performance

- Processes emails in parallel (20 concurrent validations)
- Extended timeouts for accurate SMTP verification (accuracy prioritized over speed)
- Automatic retry logic for failed verifications
- Handles rate limiting and server timeouts gracefully

## Project Structure

```
Email-validator/
├── server.js           # Main server file
├── package.json        # Dependencies and scripts
├── public/
│   └── index.html      # Web interface
├── uploads/            # Temporary CSV upload storage (auto-cleaned)
└── README.md           # This file
```

## Dependencies

### Production Dependencies
- **express**: Web framework
- **multer**: File upload handling
- **csv-parser**: CSV file parsing
- **cors**: Cross-origin resource sharing
- **email-deep-validator**: SMTP verification library
- **email-validator**: Format validation
- **mailchecker**: Disposable email detection
- **mailcheck**: Typo detection

### Development Dependencies
- **nodemon**: Auto-restart for development

## Troubleshooting

### Port Already in Use

If port 3000 is already in use, set a different port:

```bash
PORT=8080 npm start
```

### SMTP Verification Timeouts

Some mail servers block SMTP verification attempts. The validator handles this by:
- Using extended timeouts (60 seconds)
- Falling back to direct SMTP connection
- Detecting providers that block verification (Gmail, Google Workspace, Outlook) and assuming deliverability if MX records are valid

### Upload Directory Issues

The `uploads/` directory is created automatically. If you encounter permission issues, ensure the application has write permissions in the project directory.

## License

ISC

## Notes

- The validator prioritizes accuracy over speed for SMTP verification
- Some providers (Gmail, Google Workspace, Outlook) block SMTP verification but emails are still deliverable
- Validation results match the apilayer API format for compatibility
- CSV files are automatically deleted after processing

