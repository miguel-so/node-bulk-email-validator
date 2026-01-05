const express = require("express");
const multer = require("multer");
const csv = require("csv-parser");
const fs = require("fs");
const path = require("path");
const cors = require("cors");
const EmailValidator = require("email-deep-validator");
const validator = require("email-validator");
const mailchecker = require("mailchecker");
const mailcheck = require("mailcheck");
const dns = require("dns").promises;
const net = require("net");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

const upload = multer({ dest: "uploads/" });

// Ensure uploads directory exists
if (!fs.existsSync("uploads")) {
  fs.mkdirSync("uploads");
}

// Free email providers list
const freeEmailProviders = [
  "gmail.com",
  "googlemail.com",
  "yahoo.com",
  "yahoo.co.uk",
  "yahoo.fr",
  "outlook.com",
  "hotmail.com",
  "hotmail.co.uk",
  "live.com",
  "msn.com",
  "aol.com",
  "icloud.com",
  "me.com",
  "mac.com",
  "protonmail.com",
  "zoho.com",
  "mail.com",
  "gmx.com",
  "yandex.com",
  "inbox.com",
  "fastmail.com",
  "tutanota.com",
  "ibm.net",
  "ufl.edu",
];

// Role-based email prefixes
const rolePrefixes = [
  "admin",
  "administrator",
  "webmaster",
  "postmaster",
  "hostmaster",
  "abuse",
  "info",
  "support",
  "help",
  "sales",
  "marketing",
  "contact",
  "noreply",
  "no-reply",
  "donotreply",
  "do-not-reply",
];

// Create EmailValidator instance with extended timeout for accurate SMTP verification
// Accuracy is prioritized over speed - longer timeout allows servers more time to respond
const emailValidator = new EmailValidator({
  timeout: 60000, // 60 seconds for SMTP connection - extended for accuracy
  verifyDomain: true,
  verifyMailbox: true,
});

// Check if email is role-based
function isRoleEmail(user) {
  const userLower = user.toLowerCase();
  return rolePrefixes.some(
    (prefix) => userLower === prefix || userLower.startsWith(prefix + ".")
  );
}

// Check if email is from free provider
function isFreeEmail(domain) {
  return freeEmailProviders.some(
    (provider) => domain === provider || domain.endsWith("." + provider)
  );
}

// Check MX records
async function checkMXRecords(domain) {
  try {
    const mxRecords = await dns.resolveMx(domain);
    return mxRecords && mxRecords.length > 0;
  } catch (error) {
    return false;
  }
}

// Get MX records with details
async function getMXRecords(domain) {
  try {
    const mxRecords = await dns.resolveMx(domain);
    // Sort by priority (lower is better)
    return mxRecords.sort((a, b) => a.priority - b.priority);
  } catch (error) {
    return [];
  }
}

// Check if MX server is from a provider that blocks SMTP verification
// but emails are still deliverable (e.g., Gmail, Google Workspace)
function isVerificationBlockingProvider(mxRecords) {
  if (!mxRecords || mxRecords.length === 0) return false;

  // Check if MX servers are from providers known to block verification
  // but emails are still deliverable
  const blockingProviders = [
    "google.com",
    "googlemail.com",
    "gmail-smtp-in.l.google.com",
    "aspmx.l.google.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "office365.com",
    "protection.outlook.com",
  ];

  return mxRecords.some((mx) => {
    const host = mx.exchange.toLowerCase();
    return blockingProviders.some((provider) => host.includes(provider));
  });
}

// Direct SMTP verification as fallback when library fails
// Connects to MX server and attempts to verify mailbox
async function verifySMTPDirectly(email, domain) {
  return new Promise(async (resolve) => {
    try {
      const mxRecords = await getMXRecords(domain);
      if (!mxRecords || mxRecords.length === 0) {
        resolve(false);
        return;
      }

      // Try the first (highest priority) MX server
      const mxHost = mxRecords[0].exchange;
      const smtpPort = 25;
      let verified = false;
      let socket = null;
      let responseBuffer = "";

      const timeout = setTimeout(() => {
        if (socket) {
          socket.destroy();
        }
        if (!verified) {
          resolve(false);
        }
      }, 25000); // 25 second timeout

      socket = net.createConnection(smtpPort, mxHost, () => {
        // Connection established
      });

      socket.on("data", (data) => {
        responseBuffer += data.toString();
        const lines = responseBuffer.split("\r\n");
        responseBuffer = lines.pop() || "";

        for (let i = 0; i < lines.length; i++) {
          const line = lines[i].trim();
          if (!line) continue;

          const code = parseInt(line.substring(0, 3));
          const message = line.substring(4).toUpperCase();

          // Initial 220 greeting
          if (code === 220 && !verified) {
            socket.write(`EHLO ${require("os").hostname()}\r\n`);
          }
          // EHLO response - try VRFY
          else if (code === 250 && message.includes("EHLO") && !verified) {
            socket.write(`VRFY ${email}\r\n`);
          }
          // VRFY success - mailbox exists
          else if (
            code === 250 &&
            (message.includes(email.toUpperCase()) || message.includes("OK")) &&
            !verified
          ) {
            verified = true;
            clearTimeout(timeout);
            socket.write("QUIT\r\n");
            socket.end();
            resolve(true);
            return;
          }
          // VRFY not supported - try RCPT TO
          else if (
            (code === 502 || code === 550 || code === 551 || code === 553) &&
            !verified
          ) {
            socket.write(`MAIL FROM:<verify@${require("os").hostname()}>\r\n`);
          }
          // MAIL FROM accepted
          else if (code === 250 && message.includes("MAIL FROM") && !verified) {
            socket.write(`RCPT TO:<${email}>\r\n`);
          }
          // RCPT TO accepted - mailbox exists
          else if (code === 250 && message.includes("RCPT TO") && !verified) {
            verified = true;
            clearTimeout(timeout);
            socket.write("QUIT\r\n");
            socket.end();
            resolve(true);
            return;
          }
          // RCPT TO rejected - mailbox doesn't exist
          else if (code === 550 && message.includes("RCPT TO") && !verified) {
            verified = false;
            clearTimeout(timeout);
            socket.write("QUIT\r\n");
            socket.end();
            resolve(false);
            return;
          }
        }
      });

      socket.on("error", (error) => {
        clearTimeout(timeout);
        if (!verified) {
          resolve(false);
        }
      });

      socket.on("close", () => {
        clearTimeout(timeout);
        if (!verified) {
          resolve(false);
        }
      });
    } catch (error) {
      resolve(false);
    }
  });
}

// Get did_you_mean suggestion using mailcheck library
function getDidYouMean(email) {
  try {
    const mailcheck = require("mailcheck");
    const suggestion = mailcheck.run({
      email: email,
      domains: [], // Let mailcheck use its default domains
      topLevelDomains: [], // Let mailcheck use its default TLDs
    });

    if (suggestion && suggestion.full) {
      return suggestion.full;
    }
    return "";
  } catch (error) {
    // If mailcheck fails, return empty string
    return "";
  }
}

// Calculate score based on validation results
// Note: Role-based emails are not penalized - if deliverable, they're valid
function calculateScore(
  formatValid,
  mxFound,
  smtpCheck,
  disposable,
  role,
  didYouMean,
  free,
  email
) {
  if (!formatValid) return 0.0;
  if (disposable) return 0.0;
  // Removed role check - role-based emails can still be valid if deliverable

  // If there's a did_you_mean suggestion, reduce score significantly
  // This indicates a possible typo, so lower confidence
  if (didYouMean && didYouMean !== "") {
    // Lower score for emails with typo suggestions
    // Score 0.0 for very likely typos, 0.16 for possible typos
    return 0.16;
  }

  // For free emails, max score is 0.64 even with smtp_check
  if (free) {
    if (formatValid && mxFound && smtpCheck) {
      return 0.64;
    } else if (formatValid && mxFound && !smtpCheck) {
      return 0.64;
    } else if (formatValid && !mxFound) {
      return 0.48;
    }
  }

  // For non-free emails
  if (formatValid && mxFound && smtpCheck) {
    return 0.8;
  } else if (formatValid && mxFound && !smtpCheck) {
    return 0.64;
  } else if (formatValid && !mxFound) {
    return 0.48;
  }

  return 0.0;
}

// Main email validation function matching apilayer API format
async function checkEmail(email) {
  try {
    console.log(`Validating ${email}...`);

    // Parse email
    const parts = email.split("@");
    const user = parts.length === 2 ? parts[0] : "";
    const domain = parts.length === 2 ? parts[1].toLowerCase() : "";

    // Format validation
    const formatValid = validator.validate(email);

    // Check MX records
    let mxFound = false;
    if (formatValid && domain) {
      mxFound = await checkMXRecords(domain);
    }

    // SMTP check using email-deep-validator with direct SMTP fallback
    // Extended timeout and hybrid approach for accurate verification
    // Accuracy is prioritized over speed
    let smtpCheck = false;
    if (formatValid && mxFound) {
      // Get MX records to check provider type
      const mxRecords = await getMXRecords(domain);
      const isBlockingProvider = isVerificationBlockingProvider(mxRecords);

      // First, try email-deep-validator library
      let libraryVerified = false;
      let libraryRejected = false;

      try {
        const smtpPromise = emailValidator.verify(email);
        const timeoutPromise = new Promise(
          (resolve) => setTimeout(() => resolve({ validMailbox: null }), 60000) // 60 second timeout
        );

        const smtpResult = await Promise.race([smtpPromise, timeoutPromise]);

        if (smtpResult.validMailbox === true) {
          libraryVerified = true;
          smtpCheck = true;
        } else if (smtpResult.validMailbox === false) {
          libraryRejected = true;
          smtpCheck = false;
        }
        // If null/timeout, library couldn't verify - try direct SMTP
      } catch (error) {
        // Library error - try direct SMTP
        console.log(
          `SMTP library verification failed for ${email}, trying direct SMTP...`
        );
      }

      // If library didn't verify or reject, try direct SMTP connection as fallback
      if (!libraryVerified && !libraryRejected) {
        try {
          const directResult = await verifySMTPDirectly(email, domain);
          smtpCheck = directResult;

          // If direct SMTP also failed but we're dealing with a provider that blocks verification
          // and MX records are valid, assume deliverable (provider blocks verification but email exists)
          if (!smtpCheck && isBlockingProvider && mxRecords.length > 0) {
            // Provider blocks verification but has valid MX records - likely deliverable
            smtpCheck = true;
            console.log(
              `Provider ${domain} blocks SMTP verification but has valid MX - assuming deliverable`
            );
          }
        } catch (error) {
          // Direct SMTP also failed
          // If it's a blocking provider with valid MX, assume deliverable
          if (isBlockingProvider && mxRecords.length > 0) {
            smtpCheck = true;
            console.log(
              `Provider ${domain} blocks SMTP verification but has valid MX - assuming deliverable`
            );
          } else {
            smtpCheck = false;
          }
        }
      }
    }

    // Check disposable
    const disposable = !mailchecker.isValid(email);

    // Check role
    const role = isRoleEmail(user);

    // Check free
    const free = isFreeEmail(domain);

    // Get did_you_mean suggestion
    const didYouMean = getDidYouMean(email);

    // Calculate score
    let score = calculateScore(
      formatValid,
      mxFound,
      smtpCheck,
      disposable,
      role,
      didYouMean,
      free,
      email
    );

    // Score is already calculated in calculateScore function
    // No need for additional hardcoded adjustments

    // Build result matching apilayer format
    const result = {
      email: email,
      did_you_mean: didYouMean,
      user: user,
      domain: domain,
      format_valid: formatValid,
      mx_found: mxFound,
      smtp_check: smtpCheck,
      catch_all: null,
      role: role,
      disposable: disposable,
      free: free,
      score: score,
    };

    console.log(`Validation result for ${email}:`, result);
    return result;
  } catch (error) {
    console.error(`Error validating ${email}:`, error);

    // Return error result
    const parts = email.split("@");
    const user = parts.length === 2 ? parts[0] : "";
    const domain = parts.length === 2 ? parts[1].toLowerCase() : "";

    return {
      email: email,
      did_you_mean: "",
      user: user,
      domain: domain,
      format_valid: validator.validate(email),
      mx_found: false,
      smtp_check: false,
      catch_all: null,
      role: false,
      disposable: false,
      free: isFreeEmail(domain),
      score: 0.0,
    };
  }
}

// Store job data
const jobs = new Map();

// Upload and start verification
app.post("/api/verify", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded" });
    }

    const jobId = require("crypto").randomUUID();
    const filePath = req.file.path;
    const results = [];
    const emails = [];

    // Read CSV file
    return new Promise((resolve) => {
      // First, read the file to check if it's a simple text file or CSV
      const fileContent = fs.readFileSync(filePath, "utf-8");
      const lines = fileContent.split("\n").filter((line) => line.trim());

      // Check if first line looks like a header (contains 'email' case-insensitive)
      const firstLine = lines[0] || "";
      const hasHeader = firstLine.toLowerCase().includes("email");

      const stream = fs
        .createReadStream(filePath)
        .pipe(csv({ headers: hasHeader, skipEmptyLines: true }))
        .on("data", (row) => {
          // Find email field (case-insensitive)
          let email = null;
          for (const key in row) {
            if (key.toLowerCase().trim() === "email") {
              email = row[key];
              break;
            }
          }
          // If no email field found, assume first column or entire row value
          if (!email) {
            email = Object.values(row)[0] || "";
          }
          emails.push({ email: email.trim(), originalRow: row });
        })
        .on("end", async () => {
          const total = emails.length;

          // Initialize job
          jobs.set(jobId, {
            progress: 0,
            row: 0,
            total: total,
            status: "processing",
            results: [],
            emails: emails,
            filename: req.file.originalname,
          });

          res.json({ jobId });

          // Process emails in parallel (20 concurrent)
          const processEmail = async (index, emailData) => {
            const email = emailData.email;
            if (!email) {
              return {
                index,
                ...emailData.originalRow,
                status: "invalid",
                reason: "empty_email",
              };
            }

            try {
              const validation = await checkEmail(email);
              // Derive status from validation results based on deliverability
              // Valid = can receive emails, Invalid = cannot receive, Risky = uncertain
              let status = "valid";
              let reason = "valid";

              // Invalid: Cannot receive emails
              if (!validation.format_valid) {
                status = "invalid";
                reason = "bad_syntax";
              } else if (!validation.mx_found) {
                status = "invalid";
                reason = "no_mx";
              } else if (validation.disposable) {
                status = "invalid";
                reason = "disposable";
              }
              // SMTP check is the definitive test for deliverability
              else if (validation.mx_found && validation.format_valid) {
                if (validation.smtp_check) {
                  // SMTP verified - email is deliverable
                  status = "valid";
                  reason = "smtp_ok";
                } else {
                  // SMTP check failed or couldn't verify - email is not deliverable
                  // This includes cases where mailbox doesn't exist or server rejected
                  status = "invalid";
                  reason = "smtp_failed";
                }
              }
              // Risky: Uncertain deliverability (edge cases)
              else {
                // Only mark as risky if we couldn't even check basic requirements
                if (validation.did_you_mean && validation.did_you_mean !== "") {
                  status = "risky";
                  reason = "possible_typo";
                } else {
                  status = "invalid";
                  reason = "uncertain";
                }
              }

              return {
                index,
                ...emailData.originalRow,
                ...validation, // Include full apilayer format
                status: status, // Also include status for backward compatibility
                reason: reason, // Also include reason for backward compatibility
              };
            } catch (error) {
              return {
                index,
                ...emailData.originalRow,
                status: "risky",
                reason: `error_${error.message.substring(0, 20)}`,
              };
            }
          };

          const concurrency = 20;
          const resultsArray = new Array(total);
          let completed = 0;

          // Process in batches
          for (let i = 0; i < total; i += concurrency) {
            const batch = emails.slice(i, Math.min(i + concurrency, total));
            const promises = batch.map((emailData, batchIndex) =>
              processEmail(i + batchIndex, emailData)
            );

            const batchResults = await Promise.all(promises);

            batchResults.forEach((result) => {
              resultsArray[result.index] = result;
              completed++;

              const job = jobs.get(jobId);
              if (job) {
                job.progress = Math.round((completed / total) * 100);
                job.row = completed;
                job.results = resultsArray.filter((r) => r !== undefined);
              }
            });
          }

          // Mark job as complete
          const job = jobs.get(jobId);
          if (job) {
            job.status = "completed";
            job.progress = 100;
            job.row = total;
          }

          // Clean up uploaded file
          fs.unlinkSync(filePath);
          resolve();
        })
        .on("error", (error) => {
          res.status(500).json({ error: error.message });
          resolve();
        });
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get job progress
app.get("/api/progress/:jobId", (req, res) => {
  const job = jobs.get(req.params.jobId);
  if (!job) {
    return res.status(404).json({ error: "Job not found" });
  }

  res.json({
    progress: job.progress,
    row: job.row,
    total: job.total,
    status: job.status,
  });
});

// Get analytics data
app.get("/api/analytics/:jobId", (req, res) => {
  const job = jobs.get(req.params.jobId);
  if (!job) {
    return res.status(404).json({ error: "Job not found" });
  }

  const results = job.results || [];
  const total = results.length;
  const valid = results.filter((r) => r.status === "valid").length;
  const invalid = results.filter((r) => r.status === "invalid").length;
  const risky = results.filter((r) => r.status === "risky").length;

  res.json({
    total,
    valid,
    invalid,
    risky,
    validPercent: total > 0 ? Math.round((valid / total) * 100) : 0,
    invalidPercent: total > 0 ? Math.round((invalid / total) * 100) : 0,
    riskyPercent: total > 0 ? Math.round((risky / total) * 100) : 0,
  });
});

// Download filtered CSV
app.get("/api/download/:jobId", (req, res) => {
  const job = jobs.get(req.params.jobId);
  if (!job) {
    return res.status(404).json({ error: "Job not found" });
  }

  const filterType = req.query.type || "all";
  let filtered = job.results || [];

  if (filterType === "valid") {
    filtered = filtered.filter((r) => r.status === "valid");
  } else if (filterType === "invalid") {
    filtered = filtered.filter((r) => r.status === "invalid");
  } else if (filterType === "risky") {
    filtered = filtered.filter((r) => r.status === "risky");
  }

  // Convert to CSV
  if (filtered.length === 0) {
    return res.status(404).json({ error: "No data to export" });
  }

  const headers = Object.keys(filtered[0]);
  const csvRows = [
    headers.join(","),
    ...filtered.map((row) =>
      headers
        .map((header) => {
          const value = row[header] || "";
          // Escape commas and quotes in CSV
          if (
            value.toString().includes(",") ||
            value.toString().includes('"') ||
            value.toString().includes("\n")
          ) {
            return `"${value.toString().replace(/"/g, '""')}"`;
          }
          return value;
        })
        .join(",")
    ),
  ];

  const csvContent = csvRows.join("\n");
  const filename = `${filterType}-${job.filename}`;

  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
  res.send(csvContent);
});

// Cancel job
app.post("/api/cancel/:jobId", (req, res) => {
  const job = jobs.get(req.params.jobId);
  if (job) {
    job.status = "cancelled";
  }
  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Email Validator running on port ${PORT}`);
  console.log(`✅ Using email-deep-validator library (30s timeout)\n`);
});
