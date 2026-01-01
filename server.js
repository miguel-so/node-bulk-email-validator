const express = require("express");
const multer = require("multer");
const csv = require("csv-parser");
const fs = require("fs");
const path = require("path");
const dns = require("dns").promises;
const { promisify } = require("util");
const net = require("net");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

const upload = multer({ dest: "uploads/" });

// Ensure uploads directory exists
if (!fs.existsSync("uploads")) {
  fs.mkdirSync("uploads");
}

// Email validation constants
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const DISPOSABLE_DOMAINS = new Set([
  "mailinator.com",
  "10minutemail.com",
  "guerrillamail.com",
]);
const ROLE_BASED_PREFIXES = new Set([
  "info",
  "support",
  "admin",
  "sales",
  "contact",
]);

// Cache for DNS MX records
const mxCache = new Map();
const cacheLock = new Map();

// Get MX record with caching
async function getMxRecord(domain) {
  const domainLower = domain.toLowerCase();

  if (mxCache.has(domainLower)) {
    return mxCache.get(domainLower);
  }

  try {
    const records = await dns.resolveMx(domain);
    if (records && records.length > 0) {
      const mxRecord = records[0].exchange;
      mxCache.set(domainLower, mxRecord);
      return mxRecord;
    }
  } catch (error) {
    mxCache.set(domainLower, null);
    return null;
  }

  mxCache.set(domainLower, null);
  return null;
}

// SMTP check function - simplified and reliable implementation
function smtpCheck(email, mxRecord) {
  return new Promise((resolve) => {
    const TIMEOUT = 25000; // 25 seconds timeout
    const socket = new net.Socket();
    let resolved = false;
    let state = "waiting_greeting"; // waiting_greeting -> sent_helo -> sent_mail -> sent_rcpt -> done
    let buffer = "";
    let finalCode = null;

    const cleanup = () => {
      if (resolved) return;
      resolved = true;
      try {
        if (socket && !socket.destroyed) {
          socket.destroy();
        }
      } catch (e) {}
    };

    const sendCommand = (cmd) => {
      if (resolved || socket.destroyed || !socket.writable) return false;
      try {
        console.log(`SMTP: Sending ${cmd.trim()}`);
        socket.write(cmd + "\r\n");
        return true;
      } catch (e) {
        console.log(`SMTP: Error sending command: ${e.message}`);
        return false;
      }
    };

    const processBuffer = () => {
      while (buffer.includes("\r\n")) {
        const idx = buffer.indexOf("\r\n");
        const line = buffer.substring(0, idx);
        buffer = buffer.substring(idx + 2);

        if (!line.trim()) continue;

        console.log(`SMTP: Received: ${line}`);

        // Extract SMTP code
        const match = line.match(/^(\d{3})([ -])(.*)$/);
        if (!match) {
          // Try simpler pattern
          const simpleMatch = line.match(/^(\d{3})/);
          if (simpleMatch && !buffer.includes("\r\n")) {
            // Last line, use it
            const code = parseInt(simpleMatch[1]);
            handleResponse(code);
            return;
          }
          continue;
        }

        const code = parseInt(match[1]);
        const sep = match[2];

        if (sep === " ") {
          // Final line
          handleResponse(code);
          return;
        } else {
          // Continuation line - store code
          finalCode = code;
        }
      }
    };

    const handleResponse = (code) => {
      console.log(`SMTP: Handling response code ${code} in state ${state}`);

      if (state === "waiting_greeting" && code === 220) {
        state = "sent_helo";
        if (!sendCommand("HELO example.com")) {
          cleanup();
          resolve(null);
        }
      } else if (state === "sent_helo" && code === 250) {
        state = "sent_mail";
        if (!sendCommand("MAIL FROM:<verifier@example.com>")) {
          cleanup();
          resolve(null);
        }
      } else if (state === "sent_mail" && code === 250) {
        state = "sent_rcpt";
        if (!sendCommand(`RCPT TO:<${email}>`)) {
          cleanup();
          resolve(null);
        }
      } else if (state === "sent_rcpt") {
        // This is the final response we need
        sendCommand("QUIT");
        setTimeout(() => {
          cleanup();
          resolve(code);
        }, 100);
      } else if (code >= 400) {
        // Error at any stage
        sendCommand("QUIT");
        setTimeout(() => {
          cleanup();
          resolve(code);
        }, 100);
      }
    };

    socket.setTimeout(TIMEOUT);
    socket.on("timeout", () => {
      console.log(`SMTP: Timeout for ${email} on ${mxRecord}`);
      cleanup();
      resolve(null);
    });

    socket.on("error", (err) => {
      console.log(`SMTP: Error for ${email} on ${mxRecord}: ${err.message}`);
      cleanup();
      resolve(null);
    });

    socket.on("data", (chunk) => {
      if (resolved) return;
      buffer += chunk.toString();
      console.log(
        `SMTP: Raw data received (${chunk.length} bytes): ${chunk
          .toString()
          .substring(0, 100)}`
      );
      processBuffer();
    });

    socket.on("close", () => {
      if (!resolved) {
        if (state === "sent_rcpt" && finalCode !== null) {
          cleanup();
          resolve(finalCode);
        } else {
          console.log(`SMTP: Connection closed unexpectedly for ${email}`);
          cleanup();
          resolve(null);
        }
      }
    });

    // Connect
    try {
      console.log(`SMTP: Connecting to ${mxRecord}:25 for ${email}`);
      socket.setTimeout(TIMEOUT);
      socket.connect(25, mxRecord, () => {
        console.log(
          `SMTP: Connected to ${mxRecord}:25, waiting for greeting...`
        );
      });
    } catch (error) {
      console.log(`SMTP: Connection error: ${error.message}`);
      cleanup();
      resolve(null);
    }
  });
}

// Main email validation function
async function checkEmail(email) {
  // Basic syntax check
  if (!EMAIL_REGEX.test(email)) {
    return { status: "invalid", reason: "bad_syntax" };
  }

  const parts = email.split("@");
  if (parts.length !== 2) {
    return { status: "invalid", reason: "bad_syntax" };
  }

  const domain = parts[1];
  const local = parts[0];

  // Check disposable domains
  if (DISPOSABLE_DOMAINS.has(domain.toLowerCase())) {
    return { status: "invalid", reason: "disposable_domain" };
  }

  // Check role-based prefixes
  if (ROLE_BASED_PREFIXES.has(local.toLowerCase())) {
    return { status: "invalid", reason: "role_based" };
  }

  // Get MX record
  const mxRecord = await getMxRecord(domain);
  if (!mxRecord) {
    return { status: "invalid", reason: "no_mx" };
  }

  // SMTP check
  console.log(`Validating ${email} via SMTP on ${mxRecord}`);
  let code = await smtpCheck(email, mxRecord);
  console.log(`SMTP check result for ${email}: code=${code}`);

  // Retry on temporary failures
  if (code && [421, 450, 451, 452, 503].includes(code)) {
    await new Promise((resolve) => setTimeout(resolve, 2000));
    code = await smtpCheck(email, mxRecord);
  }

  if (code === 250) {
    return { status: "valid", reason: "smtp_ok" };
  } else if (code === null) {
    // Timeout - check if it's a well-known provider (likely valid but SMTP blocked)
    const wellKnownProviders = [
      "gmail.com",
      "yahoo.com",
      "outlook.com",
      "hotmail.com",
      "aol.com",
      "icloud.com",
    ];
    if (wellKnownProviders.includes(domain.toLowerCase())) {
      console.log(
        `SMTP timeout for well-known provider ${domain}, marking as valid`
      );
      return { status: "valid", reason: "smtp_timeout_well_known" };
    }
    return { status: "risky", reason: "smtp_timeout" };
  } else if ([421, 450, 451, 452, 503].includes(code)) {
    return { status: "risky", reason: `smtp_soft_fail_${code}` };
  } else if (code === 550) {
    return { status: "invalid", reason: "smtp_reject" };
  } else {
    return { status: "invalid", reason: `smtp_${code}` };
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
              return {
                index,
                ...emailData.originalRow,
                status: validation.status,
                reason: validation.reason,
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
  console.log(`✅ Using direct SMTP validation (no third-party APIs)\n`);
});
