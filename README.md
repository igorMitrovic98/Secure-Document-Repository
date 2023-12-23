# Secure Document Repository Application

This Java application serves as a secure repository for storing confidential documents, ensuring that access to a specific document is allowed only to its owner. The application provides a two-step login process for users, requiring the input of a digital certificate received during account creation. Upon successful certificate validation, users enter their username and password.

## User Authentication and Access

### Certificate Validation:

  - Users enter their digital certificate during the first step of login.
  - Valid certificates grant access to the second step.
  
### Username and Password Authentication:

  - Users input their username and password after successful certificate validation.
  - Three consecutive failed attempts result in automatic suspension of the user's certificate.
  - Suspended users can reactivate their certificate by entering correct credentials or register a new account.

### Document Access:

  - Upon successful authentication, users have access to an interface displaying a list of their documents.

## Document Management

### Document Upload:

  - Users can upload new documents.
  - Each new document is divided into N segments (N≥4, randomly generated), and each segment is stored in a different directory for enhanced security.

### Document Download:

  - Users can download existing documents.
  - The application ensures the confidentiality and integrity of each document segment.

### Document Integrity Check:

  - The application detects any unauthorized modification of stored documents.
  - Users are notified of such attempts during the download process.
  
## Public Key Infrastructure (PKI)

### Certificate Authority (CA):

  - A CA issues all certificates used in the application.
  - CA certificate, Certificate Revocation List (CRL), user certificates, and the private key of the currently logged-in user are stored in a specified file system location.

### Certificate Limitations:

  - Certificates are restricted to application-specific purposes.
  - Certificate data is associated with the corresponding user details.
  - User certificates are valid for a period of 6 months.

## Implementation Details

### File System Structure:

  - Directories for each document segment.
  - Storage of CA certificate, CRL, user certificates, and private keys.

### Security Measures:

  - Encryption and decryption of document segments.
  - Detection and notification of unauthorized document modifications.

### User Interface:

  - JavaFX-based graphical user interface.
  - Display of document lists and notifications.

### Logging and Exception Handling:

  - Utilization of a Logger class for efficient exception handling.

## Running the Application

  1. Clone the repository.
  2. Open the project in your preferred Java IDE.
  3. Run the application.
  4. Follow on-screen instructions for login, document management, and security alerts.
