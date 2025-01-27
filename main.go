// main.go
package main

import (
	"database/sql"
	"encoding/binary"
	log "github.com/sirupsen/logrus"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	_ "github.com/mattn/go-sqlite3"
)

type User struct {
    ID          uint64 `json:"id"`
    Name        string `json:"name"`
    Credentials []webauthn.Credential
}

type Server struct {
    db       *sql.DB
    webauthn *webauthn.WebAuthn
}
var sessionStore = make(map[uint64]webauthn.SessionData)

func main() {
    // Initialize SQLite database
    db, err := sql.Open("sqlite3", "passkeys.db")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    // Create tables
    _, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        );
        CREATE TABLE IF NOT EXISTS credentials (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            public_key BLOB,
            attestation_type TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    `)
    if err != nil {
        log.Fatal(err)
    }

    // Initialize WebAuthn
    web, err := webauthn.New(&webauthn.Config{
        RPDisplayName: "Passkey Demo",
        RPID:         "localhost",
        RPOrigins:    []string{"http://localhost:8080"},
    })
    if err != nil {
        log.Fatal(err)
    }

    server := &Server{
        db:       db,
        webauthn: web,
    }

    // Initialize Gin
    r := gin.Default()

    // Serve static files
    r.Static("/static", "./static")

    // Routes
    r.GET("/", server.handleHome)
    
    // Registration endpoints
    r.POST("/register", server.handleRegister)
    r.POST("/register/begin", server.handleRegisterBegin)
    r.POST("/register/finish", server.handleRegisterFinish)
    
    // Login endpoints
    r.POST("/login", server.handleLogin)
    r.POST("/login/begin", server.handleLoginBegin)
    r.POST("/login/finish", server.handleLoginFinish)
    
    // Delete endpoint
    r.DELETE("/delete", server.handleDelete)

    log.Println("Server running on http://localhost:8080")
    r.Run(":8080")
}

func (s *Server) handleHome(c *gin.Context) {
    html := `
<!DOCTYPE html>
<html>
<head>
    <title>Passkey Demo</title>
    <script src="https://unpkg.com/htmx.org@1.9.10"></script>
</head>
<body>
    <h1>Passkey Authentication Demo</h1>
    
    <div>
        <h2>Register</h2>
        <form hx-post="/register" hx-target="#message">
            <input type="text" name="username" placeholder="Username" required>
            <button type="submit">Register</button>
        </form>
    </div>

    <div>
        <h2>Login</h2>
        <form hx-post="/login" hx-target="#message">
            <input type="text" name="username" placeholder="Username" required>
            <button type="submit">Login</button>
        </form>
    </div>

    <div>
        <h2>Delete Passkey</h2>
        <form hx-delete="/delete" hx-target="#message">
            <input type="text" name="username" placeholder="Username" required>
            <button type="submit">Delete Passkey</button>
        </form>
    </div>

    <div id="message"></div>

    <script>
        // Helper function to encode ArrayBuffer to base64
        function bufferToBase64(buffer) {
            const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
            // Convert to base64URL by replacing characters that are different in base64URL encoding
            return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        }

        // Helper function to decode base64 to ArrayBuffer
        function base64ToBuffer(base64url) {
            try {
                // Convert base64URL to regular base64
                const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
                // Add padding if needed
                const padded = base64.padEnd(base64.length + (4 - (base64.length % 4)) % 4, '=');
                const binary = atob(padded);
                const buffer = new Uint8Array(binary.length);
                for (let i = 0; i < binary.length; i++) {
                    buffer[i] = binary.charCodeAt(i);
                }
                return buffer;
            } catch (err) {
                console.error('Base64 decode error:', err);
                throw new Error('Invalid base64 string');
            }
        }

        // Register functions
        async function registerPasskey(username) {
            try {
                // Begin registration
                console.log("registerPasskey");
                console.log("username: "+username);
                const optionsResp = await fetch('/register/begin', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username })
                });
                const options = await optionsResp.json();

                // Convert base64 challenge to ArrayBuffer
                options.publicKey.challenge = base64ToBuffer(options.publicKey.challenge);
                options.publicKey.user.id = base64ToBuffer(options.publicKey.user.id);

                // Create credentials
                const credential = await navigator.credentials.create({
                    publicKey: options.publicKey
                });

                // Prepare credential data for server
                const credentialData = {
                    id: credential.id,
                    rawId: bufferToBase64(credential.rawId),
                    type: credential.type,
                    response: {
                        attestationObject: bufferToBase64(credential.response.attestationObject),
                        clientDataJSON: bufferToBase64(credential.response.clientDataJSON)
                    }
                };
                alert("credentialData: "+credentialData);

                // Finish registration
                const finishResp = await fetch('/register/finish', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(credentialData)
                });

                const result = await finishResp.text();
                document.getElementById('message').innerHTML = result;
            } catch (err) {
                console.error('Registration error:', err);
                document.getElementById('message').innerHTML = 'Registration failed: ' + err.message;
            }
        }

        // Login functions
        async function loginWithPasskey(username) {
            try {
                // Begin authentication
                const optionsResp = await fetch('/login/begin', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username })
                });
                const options = await optionsResp.json();
                console.log(options);
                // Convert base64 challenge and allowCredentials to ArrayBuffer
                options.publicKey.challenge = base64ToBuffer(options.publicKey.challenge);
                if (options.publicKey.allowCredentials) {
                    options.publicKey.allowCredentials = options.publicKey.allowCredentials.map(cred => ({
                        ...cred,
                        id: base64ToBuffer(cred.id)
                    }));
                }

                // Get credentials
                const credential = await navigator.credentials.get({
                    publicKey: options.publicKey
                });

                // Prepare credential data for server
                const credentialData = {
                    id: credential.id,
                    rawId: bufferToBase64(credential.rawId),
                    type: credential.type,
                    response: {
                        authenticatorData: bufferToBase64(credential.response.authenticatorData),
                        clientDataJSON: bufferToBase64(credential.response.clientDataJSON),
                        signature: bufferToBase64(credential.response.signature),
                        userHandle: credential.response.userHandle ? bufferToBase64(credential.response.userHandle) : null
                    }
                };

                // Finish authentication
                const finishResp = await fetch('/login/finish', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(credentialData)
                });

                const result = await finishResp.text();
                document.getElementById('message').innerHTML = result;
            } catch (err) {
                console.error('Login error:', err);
                document.getElementById('message').innerHTML = 'Login failed: ' + err.message;
            }
        }

        // HTMX handlers
        document.body.addEventListener('htmx:afterRequest', function(evt) {
            if (evt.detail.pathInfo.requestPath === '/register') {
                const username = evt.detail.elt.querySelector('input[name="username"]').value;
                registerPasskey(username);
            }
            if (evt.detail.pathInfo.requestPath === '/login') {
                const username = evt.detail.elt.querySelector('input[name="username"]').value;
                alert('Login with passkey for user: ' + username);
                loginWithPasskey(username);
            }
        });
    </script>
</body>
</html>
`
    c.Header("Content-Type", "text/html")
    c.String(http.StatusOK, html)
}

func (s *Server) handleRegister(c *gin.Context) {
    username := c.PostForm("username")
    if username == "" {
        c.String(http.StatusBadRequest, "Username is required")
        return
    }

    // Check if user exists
    var exists bool
    err := s.db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE name = ?)", username).Scan(&exists)
    if err != nil {
        c.String(http.StatusInternalServerError, "Database error")
        log.WithError(err).Error("Database error")
        return
    }

    if exists {
        c.String(http.StatusOK, "User already exists")
        log.WithField("username", username).Info("User already exists")
        return
    }

    // Create new user
    result, err := s.db.Exec("INSERT INTO users (name) VALUES (?)", username)
    if err != nil {
        c.String(http.StatusInternalServerError, "Failed to create user")
        log.WithError(err).Error("Failed to create user")
        return
    }

    id, _ := result.LastInsertId() 
    c.String(http.StatusOK, "Starting registration for user: "+username, id)
}

func (s *Server) handleRegisterBegin(c *gin.Context) {
    var data struct {
        Username string `json:"username"`
    }
    if err := c.BindJSON(&data); err != nil {
        c.String(http.StatusBadRequest, "Invalid request")
        log.WithError(err).Error("Invalid request")
        return
    }

    // Get user from database
    var user User
    err := s.db.QueryRow("SELECT id, name FROM users WHERE name = ?", data.Username).Scan(&user.ID, &user.Name)
    if err != nil {
        c.String(http.StatusNotFound, "User not found")
        log.WithError(err).Error("User not found")
        return
    }

    // Generate registration options
    // options, session, err := s.webauthn.BeginRegistration(
        options, session, err := s.webauthn.BeginRegistration(
        &user,
        webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
            RequireResidentKey: BoolPtr(true),
            //TODO: look at https://pkg.go.dev/github.com/go-webauthn/webauthn@v0.11.2/protocol#UserVerificationRequirement
            UserVerification:   "required",
        }),
    )
    if err != nil {
        c.String(http.StatusInternalServerError, "Failed to begin registration")
        log.WithError(err).Error("Failed to begin registration")
        return
    }

    // Store session data (in production, use a proper session store)
    sessionStore[user.ID] = *session
    log.Println("sessionStore: ", *session)

    c.JSON(http.StatusOK, options)
}

func BoolPtr(b bool) *bool {
    return &b
}

func (s *Server) handleRegisterFinish(c *gin.Context) {
    var credential webauthn.Credential
    if err := c.BindJSON(&credential); err != nil {
        c.String(http.StatusBadRequest, "Invalid request")
        return
    }

    // Get session data (in production, get from session store)
    session := sessionStore[uint64(credential.ID[0])]
    log.Println("sessionStore: ", session)

    // Verify and create credential
    var user User
    _, err := s.webauthn.FinishRegistration(&user, session, c.Request)
    if err != nil {
        c.String(http.StatusInternalServerError, "Failed to finish registration")
        log.WithError(err).Error("Failed to finish registration")
        return
    }

    // Store credential in database
    _, err = s.db.Exec(
        "INSERT INTO credentials (id, user_id, public_key, attestation_type) VALUES (?, ?, ?, ?)",
        credential.ID, user.ID, credential.PublicKey, credential.AttestationType,
    )
    if err != nil {
        c.String(http.StatusInternalServerError, "Failed to store credential")
        log.WithError(err).Error("Failed to store credential")
        return
    }

    c.String(http.StatusOK, "Registration successful")
}

// Login handlers would be implemented similarly
func (s *Server) handleLogin(c *gin.Context) {
    username := c.PostForm("username")
    if username == "" {
        c.String(http.StatusBadRequest, "Username is required")
        return
    }
    // Implement login logic
    c.String(http.StatusOK, "Starting login for user: "+username)
}

func (s *Server) handleLoginBegin(c *gin.Context) {
    var data struct {
        Username string `json:"username"`
    }
    log.Println("Login begin")

    if err := c.BindJSON(&data); err != nil {
        c.String(http.StatusBadRequest, "Invalid request")
        log.WithError(err).Error("Invalid request")
        // print request data json 
        log.Println(data)
        return
    }
    log.Printf("Login begin for user: %s", data.Username)

    // Get user from database
    var user User
    err := s.db.QueryRow("SELECT id, name FROM users WHERE name = ?", data.Username).Scan(&user.ID, &user.Name)
    if err != nil {
        if err == sql.ErrNoRows {
            c.String(http.StatusNotFound, "User not found")
            return
        }
        log.WithError(err).Error("Database error while fetching user")
        c.String(http.StatusInternalServerError, "Database error")
        return
    }

    // Load user's credentials from database
    rows, err := s.db.Query("SELECT id, public_key, attestation_type FROM credentials WHERE user_id = ?", user.ID)
    if err != nil {
        log.WithError(err).Error("Database error while fetching credentials")
        c.String(http.StatusInternalServerError, "Database error")
        return
    }
    defer rows.Close()

    user.Credentials = []webauthn.Credential{}
    for rows.Next() {
        var cred webauthn.Credential
        err := rows.Scan(&cred.ID, &cred.PublicKey, &cred.AttestationType)
        if err != nil {
            log.WithError(err).Error("Error scanning credential row")
            continue
        }
        user.Credentials = append(user.Credentials, cred)
    }

    // Begin login
    options, session, err := s.webauthn.BeginLogin(&user)
    if err != nil {
        log.WithError(err).Error("Failed to begin login")
        c.String(http.StatusInternalServerError, "Failed to begin login")
        return
    }

    // In production, store session data in a proper session store
    // For now, we'll store it in memory (not recommended for production)
    sessionStore[user.ID] = *session

    c.JSON(http.StatusOK, options)
}



func (s *Server) handleLoginFinish(c *gin.Context) {
    var params struct {
        Username string              `json:"username"`
        Response *protocol.CredentialAssertionResponse  `json:"response"`
    }
    if err := c.BindJSON(&params); err != nil {
        c.String(http.StatusBadRequest, "Invalid request")
        return
    }

    // Get user from database
    var user User
    err := s.db.QueryRow("SELECT id, name FROM users WHERE name = ?", params.Username).Scan(&user.ID, &user.Name)
    if err != nil {
        if err == sql.ErrNoRows {
            c.String(http.StatusNotFound, "User not found")
            return
        }
        log.WithError(err).Error("Database error while fetching user")
        c.String(http.StatusInternalServerError, "Database error")
        return
    }

    // Load user's credentials
    rows, err := s.db.Query("SELECT id, public_key, attestation_type FROM credentials WHERE user_id = ?", user.ID)
    if err != nil {
        log.WithError(err).Error("Database error while fetching credentials")
        c.String(http.StatusInternalServerError, "Database error")
        return
    }
    defer rows.Close()

    user.Credentials = []webauthn.Credential{}
    for rows.Next() {
        var cred webauthn.Credential
        err := rows.Scan(&cred.ID, &cred.PublicKey, &cred.AttestationType)
        if err != nil {
            log.WithError(err).Error("Error scanning credential row")
            continue
        }
        user.Credentials = append(user.Credentials, cred)
    }

    // Get session data (in production, get from session store)
    session := sessionStore[user.ID]
    delete(sessionStore, user.ID) // Clean up after ourselves

    // Verify login
    credential, err := s.webauthn.FinishLogin(&user, session, c.Request)
    if err != nil {
        log.WithError(err).Error("Failed to finish login")
        c.String(http.StatusUnauthorized, "Login failed")
        return
    }

    // Update credential's last used time if needed
    _, err = s.db.Exec("UPDATE credentials SET last_used = CURRENT_TIMESTAMP WHERE id = ?", credential.ID)
    if err != nil {
        log.WithError(err).Error("Failed to update credential last used time")
        // Don't return error to client as login was successful
    }

    c.String(http.StatusOK, "Login successful")
}

func (s *Server) handleDelete(c *gin.Context) {
    username := c.PostForm("username")
    if username == "" {
        c.String(http.StatusBadRequest, "Username is required")
        return
    }
    // Implement delete logic
    c.String(http.StatusOK, "Passkey deleted for user: "+username)
}

// WebAuthn interface implementation
func (u *User) WebAuthnID() []byte {
    buf := make([]byte, 8)
    binary.LittleEndian.PutUint64(buf, u.ID)
    return buf
}

func (u *User) WebAuthnName() string {
    return u.Name
}

func (u *User) WebAuthnDisplayName() string {
    return u.Name
}

func (u *User) WebAuthnCredentials() []webauthn.Credential {
    return u.Credentials
}

func (u *User) WebAuthnIcon() string {
    return ""
}
