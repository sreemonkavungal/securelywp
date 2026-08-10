=== SecurelyWP – all-in-one security ===
Contributors: sreemonkavungal
Donate link: 
Tags: security, headers, vulnerability scanner, captcha, two-factor authentication (2fa)
Requires at least: 6.0
Tested up to: 6.8.2
Stable tag: 1.2.2
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

SecurelyWP is a simple security plugin that protects your WordPress site right after activation—no setup needed for most features. It instantly secures your site with powerful features, scans for risks, adds CAPTCHA and two-factor authentication, blocks repeated login attacks, and shows your site’s security status on a modern dashboard. Its firewall module now includes layered request inspection and customizable allow/deny rules for stronger protection.

== Description ==

SecurelyWP is a hassle-free security plugin that makes your WordPress site safer the moment you activate it. Most features work out of the box, with optional CAPTCHA and two-factor authentication (2FA) configuration for enhanced protection. It includes strong security features, a vulnerability scanner, system details, security headers, CAPTCHA integration, login security lockouts, and 2FA to keep your site secure and healthy.

Why Choose SecurelyWP?

* Works Out of the Box: Most security features activate automatically upon installation.
* Comprehensive Protection: Guards against hacking, malicious files, form spam, and unauthorized access.
* Lightweight: Designed to run smoothly without affecting your site’s speed or performance.
* Free Features: Includes vulnerability scanner, system details, security headers, CAPTCHA, login security lockouts, and 2FA to monitor and protect your site.

== Features ==

* Hide WordPress Version  
  * Why: Stops hackers from targeting weaknesses in your WordPress version.  
  * Impact: Good protection with no effect on your site’s appearance.

* Disable PHP Execution in Uploads Folder  
  * Why: Prevents harmful scripts from running if someone uploads a malicious file.  
  * Impact: Strong defense against file-based attacks.

* Prevent User Enumeration  
  * Why: Blocks hackers from guessing usernames through sneaky methods.  
  * Impact: Keeps your user list safe from prying eyes.

* Detect & Warn About “admin” Username  
  * Why: Alerts you if your site uses the risky “admin” username.  
  * Impact: Big security boost if you change the username.

* Disable File Editing in Dashboard  
  * Why: Stops anyone from modifying your site’s code through the WordPress dashboard.  
  * Impact: Major safeguard against unauthorized code changes.

* Force HTTPS for Login & Admin  
  * Why: Ensures your login and admin pages use a secure connection.  
  * Impact: Critical for keeping your credentials safe.

* Disable XML-RPC  
* Why: Reduces attack surface by turning off legacy remote publishing and pingback functionality.  
* Impact: Improves security and eliminates XML-RPC based attacks.

* Restrict REST API to Authenticated Users  
* Why: Blocks anonymous access to WordPress REST endpoints for better access control.  
* Impact: Strengthens privacy and reduces unauthorized data exposure.

* Disable Emojis  
* Why: Removes extra emoji scripts and styles loaded by WordPress.  
* Impact: Faster page loads and reduced frontend overhead.

* Disable Embeds  
* Why: Stops oEmbed discovery and external embed requests from loading on your site.  
* Impact: Reduces page weight and improves performance.

* Vulnerability Scanner  
  * Why: Checks your plugins, themes, and WordPress core for known security issues, while also reviewing your site’s broader security posture.  
  * Impact: Helps you find and fix risks before hackers exploit them, including outdated core/PHP, insecure settings, and missing hardening controls.

* Firewall Protection  
  * Why: Blocks suspicious requests by inspecting the request URI, query strings, user agents, referrers, POST bodies, and unusually long requests.  
  * Impact: Reduces the chance of exploitation from common web attacks while still allowing custom rules and whitelisting for trusted traffic.

* System Details  
  * Why: Shows important info about your site to monitor its health.  
  * Impact: Keeps you informed about your site’s status.

* Security Headers  
  * Why: Adds HTTP headers to improve your site’s security.  
  * Impact: Strengthens your site’s defense with minimal setup.

* CAPTCHA Protection (Cloudflare Turnstile)  
  * Why: Adds CAPTCHA to prevent spam and bot submissions.  
  * Impact: Enhances form security with user-friendly CAPTCHA.

* Two-Factor Authentication (2FA)  
  * Why: Adds an extra layer of security by requiring a second verification step during login.  
  * Impact: Significantly reduces the risk of unauthorized access.  

* Login Security Protection  
  * Why: Blocks repeated failed login attempts from the same IP after a configurable threshold.  
  * Impact: Helps prevent brute-force attacks and reduces password guessing risk.  

**2FA Features:**  
- Authenticator App (TOTP): Use apps like Google Authenticator or Authy for time-based codes.  
- Email 2FA: Receive codes via email for verification.  
- Recovery Codes: Generate emergency codes for access if other methods are unavailable.  
- Per-User Settings: Each user can configure their own 2FA preferences.  
- Multisite Support: Super admins can enforce 2FA network-wide.  
- Flexible Options: Choose primary 2FA method from TOTP, Email 2FA, or Recovery Codes.  

**Supported Forms, Plugins & Multisite for CAPTCHA:**  
- Core WordPress: Login, Registration, Lost Password, Comment  
- E-commerce & Membership: WooCommerce Checkout, MemberPress, Ultimate Member, WP-Members  
- Form Plugins: WPForms, Gravity Forms, Contact Form 7 (CF7), Formidable Forms, Forminator, Elementor Pro, Easy Digital Downloads (EDD), Mailchimp for WordPress  
- Community / Forums: BuddyPress, bbPress  
- Multisite: Multisite Signup Forms  

== How to Set Up CAPTCHA with Cloudflare Turnstile ==

1. **Sign Up for Cloudflare:** Go to https://www.cloudflare.com/ and create a free account or log in.  
2. **Add Your Site:** Click "Add a Site" in the dashboard and enter your domain.  
3. **Access Turnstile:** Navigate to the "Turnstile" section in the Cloudflare dashboard.  
4. **Create a Turnstile Widget:**  
   * Click "Add Widget"  
   * Provide a name (e.g., "SecurelyWP CAPTCHA")  
   * Add Hostnames (your domain, e.g., example.com) → Click "Add"  
   * Choose the widget type ("Managed")  
5. **Get Your Keys:** Copy the Site Key and Secret Key.  
6. **Add Keys to SecurelyWP:** Go to SecurelyWP > CAPTCHA Settings in WordPress → paste keys → enable CAPTCHA for desired forms.  
7. **Test Your CAPTCHA:** Visit a form to ensure the CAPTCHA widget appears and works correctly.  

== How to Set Up Two-Factor Authentication ==

1. **Access 2FA Settings:** Go to "Profile" > "Two-Factor Authentication" in your WordPress dashboard.  
2. **Enable 2FA Methods:**  
   * Authenticator App: Scan the QR code or enter the secret into your app (Google Authenticator, Authy). Verify with a code.  
   * Email 2FA: Enable to receive codes via email.  
   * Recovery Codes: Generate emergency codes. Copy or download codes for safekeeping.  
3. **Choose Primary Method:** Select your preferred 2FA method (Authenticator App, Email, or Recovery Codes).  
4. **Test 2FA:** Log out and log in to verify the 2FA prompt appears below the login form.  
5. **Multisite (Super Admins):** Enable network-wide 2FA enforcement for all users.  

== Installation ==

1. Go to "Plugins" > "Add New," search for "SecurelyWP," click "Install Now" and "Activate."  
2. Or upload the plugin ZIP file via "Plugins" > "Add New" > "Upload Plugin."  
3. Automatic Protection: Most features start protecting your site immediately upon activation.  
4. Optional CAPTCHA Setup: Go to SecurelyWP > CAPTCHA Settings and add your Cloudflare Turnstile keys.  
5. Optional 2FA Setup: Go to "Profile" > "Two-Factor Authentication" to configure 2FA.  
6. Check Dashboard: Visit "SecurelyWP" to view site health, scan for risks, or configure settings.  
7. Review Security Assessment: Run a vulnerability scan to see prioritized issues, recommendations, and environment-based findings.  

== Frequently Asked Questions ==

= Do I need to configure anything after installing SecurelyWP? =  
Most features work automatically. For CAPTCHA, add Cloudflare Turnstile keys. For 2FA, configure under "Profile" > "Two-Factor Authentication."

= Will this plugin slow down my site? =  
No, SecurelyWP is lightweight and won’t affect performance.

= Does it work with my theme or other plugins? =  
Yes, SecurelyWP works with any theme and most plugins.

= What if my site doesn’t have HTTPS? =  
"Force HTTPS" requires SSL. Other features, including 2FA, work fine without HTTPS.

= How often does the vulnerability scanner run? =  
It runs automatically in the background and can be checked anytime.

= Can I use SecurelyWP on a multisite? =  
Yes, including signup forms for CAPTCHA and network-wide 2FA.

= Where do I get Cloudflare Turnstile keys? =  
Sign up at Cloudflare, add your site, and create a Turnstile widget.

= How do I set up 2FA for my account? =  
Go to "Profile" > "Two-Factor Authentication," enable your preferred methods, and follow setup instructions.

== Screenshots ==

1. Dashboard: Overview of your site’s security status, including CAPTCHA and 2FA settings.  
2. Vulnerability Scanner: View scan results to identify and fix risks.  
3. System Details: Clear report of your site’s version, themes, and more.  
4. Security Headers: Overview of active HTTP security headers.  
5. CAPTCHA Settings: Configure Cloudflare Turnstile and enable CAPTCHA for forms.  
6. Two-Factor Authentication: Configure 2FA methods and view recovery codes.  
7. Login Security: Configure lockout thresholds and monitor recent lockout activity.  

== Changelog ==

= 1.2.2 =
* Added Login Security settings page with configurable failed-login lockout protection.
* Added dashboard support for Login Security status, threshold, and recent lockout activity.
* Expanded the vulnerability scanner with broader security assessments, including PHP/core checks, SSL detection, debug mode warnings, and hardening guidance.
* Enhanced the firewall with granular inspection controls for request URIs, query strings, user agents, referrers, POST bodies, and long requests.
* Improved plugin documentation and release metadata for the new security module.

= 1.2.1 =
* Added advanced hardening features: Disable XML-RPC, Restrict REST API, Disable Emojis, and Disable Embeds.
* Improved hardening defaults for existing installations during upgrade.
* Updated dashboard hardening count to reflect the expanded feature set.
* Bumped plugin version metadata and stable tag to 1.2.1.

= 1.2.0 =
* Added upgrade routine for 1.2.0 to ensure default options exist after updates.
* Fixed readme compatibility information and version consistency across plugin metadata.
* Prepared plugin versioning and upgrade path for the next release.

= 1.1.0 =
* Fixed: 2FA login flow now uses secure cookie-based state instead of PHP session_id().
* Fixed: Dashboard vulnerability counts now read from scanner results.
* Fixed: Dashboard 2FA user count now reflects actually enabled users.
* Fixed: Firewall test dialog uses WordPress core jQuery UI Dialog.
* Fixed: Cache purger no longer deletes all site transients.
* Fixed: Vulnerability scanner caches Wordfence API response for faster scans.
* Fixed: Scheduled vulnerability scans register on activation and plugin load.
* Fixed: Firewall now inspects referrer headers and POST bodies.
* Fixed: CAPTCHA verification added for MemberPress, Ultimate Member, and WP-Members.
* Fixed: HSTS header is only sent over HTTPS connections.
* Improved: Recovery codes are hashed before storage.
* Improved: System Details page caches filesystem counts with manual refresh.
* Improved: Added upgrade routine and uninstall cleanup.
* Improved: Added firewall status card to the dashboard.
* Improved: Brute force protection and firewall logging use client IP detection behind proxies.

= 1.0.9 =
* Added comprehensive cache purging system with admin bar button.
* Added support for purging WordPress internal cache, object cache, transients, and opcode cache.
* Added detection and purging of popular caching plugin caches (WP Super Cache, W3 Total Cache, LiteSpeed Cache, WP Rocket, etc.).
* Added browser cache refresh functionality with asset versioning.

= 1.0.8 =
* Added Firewall.  

= 1.0.7 =  
* Added Two-Factor Authentication (2FA) with Authenticator App (TOTP), Email 2FA, and Recovery Codes.  
* Added per-user 2FA settings under Profile for all roles.  
* Added multisite support for network-wide 2FA enforcement by super admins.  
* Added 2FA form below WordPress login with verification.  

= 1.0.6 =  
* Added CAPTCHA Protection using Cloudflare Turnstile for forms.  

= 1.0.5 =  
* Added Security Headers feature with industry-standard HTTP headers.  

= 1.0.4 =  
* Added Hide WordPress Version  
* Added Disable PHP Execution in Uploads Folder  
* Added Prevent User Enumeration  
* Added Detect & Warn About “admin” Username  
* Added Disable File Editing in Dashboard  
* Added Force HTTPS for Login & Admin  
* Added Basic Brute Force Protection  
* Added Vulnerability Scanner  
* Added System Details  
* Major features released
