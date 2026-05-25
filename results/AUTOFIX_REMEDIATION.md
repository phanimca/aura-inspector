# Aura Inspector — Salesforce Auto-Fix Remediation Guide

**Target:** `https://philipsb2c--b2cpartial.sandbox.my.site.com/producttesterprogram`  
**Scan Date:** 2026-05-25  
**Author:** Phani · phani.dummy@hotmail.com  
**Mode:** Guest / Unauthenticated  
**Risk Score:** 78 / 100 (High)

---

## How to use this file

Each section below maps directly to a finding from the scan.  
Every section provides:
- **Setup steps** (declarative — no code)
- **Apex / SOQL code fix** (copy-paste ready)
- **Guest Profile permission matrix** (what to turn off)
- **Test assertion** to verify the fix closed the exposure

---

## FIX-01 · User Object PII Exposure (HIGH)

**Finding:** `User` object is readable via Aura API and GraphQL by unauthenticated guests.  
**OWASP:** `API3:2023` — Broken Object Property Level Authorization

### Salesforce Setup (declarative)

1. **Setup → Profiles → Site Guest User (producttesterprogram)**
2. Scroll to **Object Settings → User**
3. Set Read access → **None**
4. Scroll to **Field-Level Security → User**
5. Remove Read on: `Email`, `Phone`, `MobilePhone`, `Name`, `Username`, `ProfileId`
6. Save

### Apex — Enforce FLS on all User queries

```apex
// BEFORE (insecure — no FLS enforcement)
List<User> users = [SELECT Id, Name, Email FROM User WHERE IsActive = true];

// AFTER — enforce field-level security
List<User> users = [
    SELECT Id, Name, Email
    FROM User
    WHERE IsActive = true
    WITH SECURITY_ENFORCED          // throws QueryException if FLS denied
];

// Alternative: use Security.stripInaccessible()
SObjectAccessDecision decision = Security.stripInaccessible(
    AccessType.READABLE,
    [SELECT Id, Name, Email, Phone FROM User WHERE IsActive = true]
);
List<User> safeUsers = (List<User>) decision.getRecords();
```

### Apex Controller (Experience Cloud / Aura)

```apex
// BEFORE — exposes user fields directly
@AuraEnabled(cacheable=true)
public static List<User> getUsers() {
    return [SELECT Id, Name, Email FROM User LIMIT 50];
}

// AFTER — restrict to current user only, no guest access
@AuraEnabled(cacheable=true)
public static Map<String, String> getCurrentUserInfo() {
    // Reject guest users entirely
    if (UserInfo.getUserType() == 'Guest') {
        throw new AuraHandledException('Access denied for guest users.');
    }
    return new Map<String, String>{
        'name'  => UserInfo.getName(),
        'email' => UserInfo.getUserEmail()
    };
}
```

### Test assertion (verify fix)

```apex
@IsTest
static void guestCannotReadUsers() {
    User guestUser = [SELECT Id FROM User WHERE UserType = 'Guest' LIMIT 1];
    System.runAs(guestUser) {
        try {
            List<User> result = [SELECT Email FROM User WITH SECURITY_ENFORCED];
            System.assert(result.isEmpty(), 'Guest should not read User records');
        } catch (System.QueryException e) {
            // Expected — FLS correctly blocked the query
            System.assert(e.getMessage().contains('SECURITY_ENFORCED'), e.getMessage());
        }
    }
}
```

---

## FIX-02 · ContentDocument / ContentVersion File Exposure (HIGH)

**Finding:** File objects are readable via guest session — actual file binaries may be downloadable.  
**OWASP:** `API1:2023` — Broken Object Level Authorization

### Salesforce Setup (declarative)

1. **Setup → Profiles → Site Guest User**
2. **Object Settings → ContentDocument** → Read: **None**
3. **Object Settings → ContentVersion** → Read: **None**
4. **Object Settings → ContentWorkspace** → Read: **None**
5. Review **Sharing Settings**: ensure `ContentDocument` `OwnerId` is not guest-visible
6. **Setup → Content Deliveries and Public Links** → Disable for guest

### Apex — Remove public ContentDocumentLink sharing

```apex
// BEFORE — insecure public share
ContentDocumentLink cdl = new ContentDocumentLink();
cdl.ContentDocumentId = doc.Id;
cdl.LinkedEntityId    = communityId;        // links to Experience Site = public!
cdl.ShareType         = 'V';
cdl.Visibility        = 'AllUsers';         // DANGEROUS
insert cdl;

// AFTER — restrict to internal users only
ContentDocumentLink cdl = new ContentDocumentLink();
cdl.ContentDocumentId = doc.Id;
cdl.LinkedEntityId    = ownerId;
cdl.ShareType         = 'I';                // Inferred permissions
cdl.Visibility        = 'InternalUsers';    // Not visible to guests
insert cdl;
```

### Apex Controller — Block guest file access

```apex
@AuraEnabled(cacheable=true)
public static List<ContentDocument> getFiles() {
    if (UserInfo.getUserType() == 'Guest') {
        throw new AuraHandledException('File access is not available to guest users.');
    }
    return [
        SELECT Id, Title, FileType, ContentSize
        FROM ContentDocument
        WITH SECURITY_ENFORCED
        LIMIT 50
    ];
}
```

### Test assertion

```apex
@IsTest
static void guestCannotAccessFiles() {
    User guestUser = [SELECT Id FROM User WHERE UserType = 'Guest' LIMIT 1];
    System.runAs(guestUser) {
        try {
            ContentDocumentController.getFiles();
            System.assert(false, 'Should have thrown AuraHandledException');
        } catch (AuraHandledException e) {
            System.assert(true, 'Correctly blocked guest file access');
        }
    }
}
```

---

## FIX-03 · GraphQL uiapi Guest Exposure (HIGH)

**Finding:** 19 objects exposed via GraphQL `uiapi` including Profile (120), StaticResource (571), LiveChatButton (440).  
**OWASP:** `API5:2023` — Broken Function Level Authorization

### Salesforce Setup (declarative)

1. **Experience Cloud → Administration (your site) → Security**
2. Disable **"Clickjack protection level"** — ensure it is set to **Allow framing by same origin only**
3. **Setup → Session Settings** → Disable **Lightning Web Security for guest**
4. **Setup → Profiles → Site Guest User → Object Settings:**

| Object | Read | Change to |
|---|---|---|
| Profile | ✅ | ❌ Remove |
| StaticResource | ✅ | ❌ Remove |
| LiveChatButton | ✅ | ❌ Remove |
| EntityDefinition | ✅ | ❌ Remove |
| BusinessHours | ✅ | ❌ Remove (if not needed) |
| ProcessDefinition | ✅ | ❌ Remove |
| AppMenuItem | ✅ | ❌ Remove |
| RecordType | ✅ | ❌ Review |

### Apex — Guard all uiapi-accessible controllers

```apex
// Add this utility to a shared Apex class
public class GuestGuard {
    public static void denyGuest() {
        if (UserInfo.getUserType() == 'Guest') {
            throw new AuraHandledException(
                'This operation requires an authenticated session.'
            );
        }
    }
}

// Use in every @AuraEnabled method
@AuraEnabled(cacheable=true)
public static List<SObject> getSensitiveData() {
    GuestGuard.denyGuest();
    return [SELECT Id FROM SensitiveObject__c WITH SECURITY_ENFORCED];
}
```

---

## FIX-04 · EntityDefinition Schema Exposure (MEDIUM)

**Finding:** Full org schema (286 objects) readable by guest — enables targeted SOQL attack crafting.  
**OWASP:** `API9:2023` — Improper Inventory Management

### Apex — Never expose EntityDefinition to guests

```apex
// REMOVE any Apex that queries EntityDefinition from a guest-accessible controller
// BEFORE (insecure)
@AuraEnabled(cacheable=true)
public static List<EntityDefinition> getObjects() {
    return [SELECT QualifiedApiName, Label FROM EntityDefinition LIMIT 500];
}

// AFTER — completely remove or guard
@AuraEnabled(cacheable=true)
public static List<EntityDefinition> getObjects() {
    GuestGuard.denyGuest();
    // Only return a curated allow-list, never the full org schema
    Set<String> allowList = new Set<String>{'Product2', 'Case'};
    return [
        SELECT QualifiedApiName, Label
        FROM EntityDefinition
        WHERE QualifiedApiName IN :allowList
        WITH SECURITY_ENFORCED
    ];
}
```

---

## FIX-05 · SOAP API Enabled (MEDIUM)

**Finding:** SOAP endpoint accessible — allows credential-based brute-force attacks.  
**OWASP:** `API8:2023` — Security Misconfiguration

### Salesforce Setup (declarative)

1. **Setup → Session Settings**
2. Uncheck **"Enable API Access"** for the Guest User Profile
3. **Setup → Connected Apps → [Your Connected App]**
4. Set **"IP Relaxation"** to **Enforce IP restrictions**
5. Set **"Permitted Users"** to **Admin approved users are pre-authorized**
6. **Setup → Network Access** → Add corporate IP ranges to allowlist

### Network-level block (if using Salesforce Shield or a WAF)

```
# Block SOAP endpoint for non-corporate IPs at WAF level
# Paths to block for unauthenticated/guest access:
#   /services/Soap/u/
#   /services/Soap/m/
#   /services/Soap/s/
# Allow only: corporate IP CIDR blocks
```

---

## FIX-06 · Calendar Record Exposure — 2,000 Records (MEDIUM)

**Finding:** 2,000 Calendar records readable without authentication.  
**OWASP:** `API1:2023`

### Apex — Restrict Calendar queries

```apex
// BEFORE
@AuraEnabled(cacheable=true)
public static List<Event> getCalendarEvents() {
    return [SELECT Subject, StartDateTime, EndDateTime, OwnerId FROM Event LIMIT 100];
}

// AFTER — scope to guest-safe public events only, or block entirely
@AuraEnabled(cacheable=true)
public static List<Event> getPublicEvents() {
    if (UserInfo.getUserType() == 'Guest') {
        // Only return events explicitly marked as public
        return [
            SELECT Subject, StartDateTime, EndDateTime
            FROM Event
            WHERE IsPrivate = false
              AND ShowAs = 'Public'
            WITH SECURITY_ENFORCED
            LIMIT 50
        ];
    }
    return [SELECT Subject, StartDateTime, EndDateTime FROM Event WITH SECURITY_ENFORCED LIMIT 100];
}
```

---

## FIX-07 · LiveChatButton Configuration Exposure (MEDIUM)

**Finding:** 440 LiveChatButton configuration objects readable via GraphQL.

### Salesforce Setup

1. **Setup → Profiles → Site Guest User → Object Settings → LiveChatButton** → Read: **None**
2. If chat buttons must be rendered on guest pages, load config server-side only — never expose the raw object to GraphQL

### Apex — Provide only the minimum needed for chat rendering

```apex
// BEFORE — returns full LiveChatButton record
@AuraEnabled(cacheable=true)
public static LiveChatButton getChatConfig(String buttonId) {
    return [SELECT Id, DeveloperName, ChatPageId, OptionsHasPrechatApi
            FROM LiveChatButton WHERE Id = :buttonId];
}

// AFTER — return only the button ID needed for the Snap-ins snippet
@AuraEnabled(cacheable=true)
public static String getChatButtonId() {
    // Return hard-coded or metadata-driven value — never expose the full object
    return Label.Chat_Button_Id;  // Store in Custom Label
}
```

---

## FIX-08 · CSP Wildcard Origin Hardening (MEDIUM)

**Finding:** 6 wildcard CSP entries increase supply-chain attack surface.

### Replace wildcards in Experience Cloud CSP

```
# Setup → Security → Content Security Policy → Trusted Sites

# REMOVE these wildcards:
*.adobe.io
*.sproutsocial.com
*.appdynamics.com
*.eum-appdynamics.com
*.vf.force.com
*.philips.co.uk

# REPLACE with explicit entries:
https://assets.adobedtm.com          # instead of *.adobe.io
https://data.sproutsocial.com        # instead of *.sproutsocial.com
https://cdn.appdynamics.com          # instead of *.appdynamics.com
https://col.eum-appdynamics.com      # instead of *.eum-appdynamics.com
https://c.vf.force.com               # instead of *.vf.force.com
https://www.philips.co.uk            # instead of *.philips.co.uk
https://acc.philips.co.uk
```

### Add Subresource Integrity to static scripts (LWC)

```javascript
// In your LWC component or Experience Builder page
// Add integrity checks for third-party scripts
const script = document.createElement('script');
script.src = 'https://www.googletagmanager.com/gtm.js?id=GTM-XXXXX';
script.integrity = 'sha384-<base64-hash>';   // generate with: openssl dgst -sha384 -binary <file> | openssl base64
script.crossOrigin = 'anonymous';
document.head.appendChild(script);
```

---

## FIX-09 · Guest User Profile — Master Permission Checklist

Run this checklist in **Setup → Profiles → [Site] Guest User → Object Settings**:

```
[ ] User              → Read: REMOVE
[ ] ContentDocument   → Read: REMOVE
[ ] ContentVersion    → Read: REMOVE
[ ] ContentWorkspace  → Read: REMOVE
[ ] EntityDefinition  → Read: REMOVE
[ ] Profile           → Read: REMOVE
[ ] LiveChatButton    → Read: REMOVE
[ ] StaticResource    → Read: REVIEW (needed for CSS/JS assets?)
[ ] RecordType        → Read: REVIEW
[ ] ProcessDefinition → Read: REMOVE
[ ] AppMenuItem       → Read: REMOVE
[ ] BusinessHours     → Read: REMOVE (unless used in guest UI)
[ ] Calendar / Event  → Read: REMOVE (or scope to ShowAs=Public only)
[ ] Network           → Read: REMOVE (if not needed by your LWC components)
[ ] Topic             → Read: REVIEW
```

HTTP / Infrastructure:
```
[ ] HSTS header               → Add to CDN/WAF or Experience Cloud HTTP Headers
[ ] X-Frame-Options           → Add: SAMEORIGIN
[ ] X-Content-Type-Options    → Add: nosniff
[ ] Referrer-Policy           → Add: strict-origin-when-cross-origin
[ ] Permissions-Policy        → Add: camera=(), microphone=(), geolocation=()
[ ] CSP wildcards (6 entries) → Replace with explicit subdomains
[ ] Cookie flags              → Ensure Secure; HttpOnly; SameSite=Strict on all session cookies
[ ] Screen Flow run mode      → Set to User Context for all guest-accessible flows
[ ] Login retURL              → Validate against domain allowlist before redirecting
```

---

## FIX-10 · Shared GuestGuard Apex Utility Class

Copy this to your org as a shared utility for all Experience Cloud Apex controllers:

```apex
/**
 * GuestGuard — shared security utility for Experience Cloud Apex controllers.
 * Author : Phani <phani.dummy@hotmail.com>
 * Purpose: Centralise guest-user rejection and FLS enforcement helpers.
 */
public with sharing class GuestGuard {

    /** Throws AuraHandledException if the current user is a guest. */
    public static void denyGuest() {
        if (UserInfo.getUserType() == 'Guest') {
            throw new AuraHandledException(
                'This operation is not available to unauthenticated users.'
            );
        }
    }

    /**
     * Strips fields the current user cannot read.
     * Use before returning records to the client.
     */
    public static List<SObject> stripInaccessible(List<SObject> records) {
        SObjectAccessDecision decision =
            Security.stripInaccessible(AccessType.READABLE, records);
        return decision.getRecords();
    }

    /**
     * Returns true when the caller is an internal (non-guest, non-portal) user.
     */
    public static Boolean isInternalUser() {
        String userType = UserInfo.getUserType();
        return (userType == 'Standard' || userType == 'PowerPartner');
    }
}
```

### Test class for GuestGuard

```apex
@IsTest
private class GuestGuardTest {

    @IsTest
    static void denyGuest_throwsForGuestUser() {
        User guestUser = createGuestUser();
        System.runAs(guestUser) {
            try {
                GuestGuard.denyGuest();
                System.assert(false, 'Expected AuraHandledException');
            } catch (AuraHandledException e) {
                System.assert(
                    e.getMessage().contains('unauthenticated'),
                    'Message should mention unauthenticated: ' + e.getMessage()
                );
            }
        }
    }

    @IsTest
    static void denyGuest_doesNotThrowForInternalUser() {
        GuestGuard.denyGuest(); // running as test user (internal) — should not throw
        System.assert(true, 'Internal user passed guard correctly');
    }

    private static User createGuestUser() {
        return [SELECT Id FROM User WHERE UserType = 'Guest' LIMIT 1];
    }
}
```

---

---

## FIX-11 · Missing HTTP Security Headers (HIGH / MEDIUM)

**Finding:** HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy headers are absent from all responses.  
**OWASP:** `API8:2023` — Security Misconfiguration

### Add via Experience Cloud HTTP Response Headers

1. **Setup → Security → HTTP Response Headers**
2. Add each header below:

| Header | Value |
|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `X-Frame-Options` | `SAMEORIGIN` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` |

### Add via CDN/WAF (recommended for HSTS)

```nginx
# Nginx example
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
```

### Test assertion

```bash
# Verify headers are present
curl -sI https://philipsb2c--b2cpartial.sandbox.my.site.com/producttesterprogram | grep -iE "strict-transport|x-frame|x-content|referrer"
```

---

## FIX-12 · Insecure Session Cookie Flags (MEDIUM)

**Finding:** Session cookies are missing `HttpOnly`, `Secure`, and/or `SameSite=Strict` attributes.  
**OWASP:** `API2:2023` — Broken Authentication

### Salesforce Setup (declarative)

1. **Setup → Session Settings**
2. Enable ✅ **"Lock sessions to the IP address from which they originated"**
3. Enable ✅ **"Use POST requests for cross-site form submissions"** (CSRF mitigation)
4. Set **Session Timeout** to 30 minutes or less for guest sessions

### Apex — Set secure flags on any custom cookies

```apex
// BEFORE — insecure custom cookie
Cookie insecureCookie = new Cookie('myToken', tokenValue, null, -1, false);
ApexPages.currentPage().setCookies(new Cookie[] { insecureCookie });

// AFTER — all security flags set
Cookie secureCookie = new Cookie(
    'myToken',
    tokenValue,
    null,       // path — set to '/' or your site prefix
    -1,         // maxAge — -1 = session cookie
    true        // isSecure = true
);
// Note: Apex does not expose HttpOnly/SameSite setters directly.
// Use a Visualforce controller or set cookies via CDN/WAF instead.
ApexPages.currentPage().setCookies(new Cookie[] { secureCookie });
```

### Test assertion

```bash
curl -sI https://philipsb2c--b2cpartial.sandbox.my.site.com/producttesterprogram \
  | grep -i "set-cookie" \
  | grep -iE "httponly|samesite|secure"
# All session cookie lines should contain: Secure; HttpOnly; SameSite=Strict
```

---

## FIX-13 · Lightning Screen Flow Guest Access (MEDIUM)

**Finding:** `FlowController/getFlowMetadata` accessible without authentication. Screen Flows running in system context may perform DML as guest users.  
**OWASP:** `API5:2023` — Broken Function Level Authorization

### Salesforce Setup (declarative)

1. **Setup → Flows → [each flow used on guest pages]**
2. Click **Edit** → **Run Settings**
3. Set **Run Flow As** → **User or System Context — Default** (not System Context — Without Sharing)
4. In **Experience Cloud site → Administration → Flows**, review which flows are exposed to guest users

### Apex — Guard any Apex method invoked by guest-accessible Flows

```apex
// BEFORE — Flow invokes this Apex action without auth check
@InvocableMethod(label='Create Case' description='Creates a support case')
public static List<Id> createCase(List<CaseInput> inputs) {
    // No guest check!
    Case c = new Case(Subject = inputs[0].subject);
    insert c;
    return new List<Id>{ c.Id };
}

// AFTER — explicit guest rejection
@InvocableMethod(label='Create Case' description='Creates a support case')
public static List<Id> createCase(List<CaseInput> inputs) {
    if (UserInfo.getUserType() == 'Guest') {
        throw new AuraHandledException('Unauthenticated case creation is not permitted.');
    }
    Case c = new Case(Subject = inputs[0].subject);
    insert c;
    return new List<Id>{ c.Id };
}
```

### Test assertion

```apex
@IsTest
static void guestCannotInvokeFlow() {
    User guestUser = [SELECT Id FROM User WHERE UserType = 'Guest' LIMIT 1];
    System.runAs(guestUser) {
        try {
            FlowController.createCase(new List<CaseInput>{ new CaseInput() });
            System.assert(false, 'Should have thrown');
        } catch (AuraHandledException e) {
            System.assert(true, 'Guest blocked correctly');
        }
    }
}
```

---

## FIX-14 · Open Redirect via Login retURL (MEDIUM)

**Finding:** The login endpoint accepts arbitrary external URLs via the `retURL` parameter and redirects to them, enabling phishing via legitimate-looking Salesforce links.  
**OWASP:** `API8:2023` — Security Misconfiguration

### Salesforce Setup

1. **Setup → My Domain** → Verify your domain is registered (limits redirect scope)
2. **Setup → Session Settings** → Enable **"Require HttpOnly attribute"** for session cookies
3. Add a **Login Flow** to intercept and validate `retURL` before redirection

### Apex Login Flow — Validate retURL allowlist

```apex
public class ReturnUrlValidator {

    private static final Set<String> ALLOWED_HOSTS = new Set<String>{
        'philipsb2c--b2cpartial.sandbox.my.site.com',
        'www.philips.com'
    };

    @AuraEnabled
    public static String validateReturnUrl(String returnUrl) {
        if (String.isBlank(returnUrl)) {
            return '/'; // safe default
        }
        try {
            URL parsed = new URL(returnUrl);
            if (ALLOWED_HOSTS.contains(parsed.getHost())) {
                return returnUrl;
            }
        } catch (Exception e) {
            // Malformed URL — reject
        }
        return '/'; // redirect to home if URL is external
    }
}
```

### Test assertion

```bash
# Should NOT redirect to evil.example.com
curl -sI "https://philipsb2c--b2cpartial.sandbox.my.site.com/producttesterprogram/login?retURL=https://evil.example.com" \
  | grep -i location
# Expected: Location should point to /login or /home, NOT evil.example.com
```

---

## Verification Checklist — Post-Fix

Run these checks after applying fixes:

```
[ ] Guest curl: curl -s "https://<site>/s/sfsites/aura" -d '...' returns no User data
[ ] Guest curl: GraphQL query for Profile returns 0 records
[ ] Apex test suite: all GuestGuardTest methods pass
[ ] Manual: open /recordlist/Topic/Default in incognito — verify redirect to login
[ ] SOAP: attempt login via /services/Soap/u/ — verify IP restriction fires
[ ] Headers: curl -sI <site> | grep -iE "strict-transport|x-frame|x-content" shows all headers
[ ] Cookies: curl -sI <site> | grep -i set-cookie — all lines contain Secure; HttpOnly; SameSite
[ ] Flow: verify FlowController probe returns ACCESS DENIED for guest session
[ ] Redirect: curl retURL=https://evil.example.com — confirm redirect stays on own domain
[ ] Re-run aura-inspector: risk score should drop below 30
```

### Re-scan command (verify fixes)

```powershell
.venv\Scripts\python.exe src/aura_cli.py `
    -U phani `
    -u "https://philipsb2c--b2cpartial.sandbox.my.site.com/producttesterprogram" `
    --app /s `
    --aura /s/sfsites/aura `
    -k `
    -o ./results/post-fix
```

---

*Generated by Aura Inspector · Author: Phani · phani.dummy@hotmail.com · 2026-05-25*
