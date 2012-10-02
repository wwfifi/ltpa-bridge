package net.unicon.ltpabridge;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;
import java.util.Date;

import javax.servlet.http.Cookie;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Lightweight Third Party Authentication. Generates and validates ltpa tokens used in Domino single sign on
 * environments. Does not work with WebSphere SSO tokens. You need a properties file named LtpaToken.properties which
 * holds two properties.
 * 
 * <pre>
 * ) domino.secret=The base64 encoded secret found in the field LTPA_DominoSecret in the SSO configuration document.
 * ) cookie.domain=The domain you want generated cookies to be from. e.g. '.domain.com' (Note the leading dot)
 *</pre>
 * 
 * @author $Author: rkelly $
 * @version $Revision: 1.1 $
 * @created $Date: 2003/04/07 18:22:14 $
 */
public final class LtpaToken {
	
    private static final Logger log = LoggerFactory.getLogger(LtpaToken.class);
    private byte[] creation;
    private Date creationDate;
    private byte[] digest;
    private byte[] expires;
    private Date expiresDate;
    private byte[] header;
    private String ltpaToken;
    private byte[] rawToken;
    private byte[] user;
    private String dominoSecret;
    /**
     * Constructor for the LtpaToken object
     * 
     * @param token
     *            Description of the Parameter
     */
    public LtpaToken(String token, String cookieName, String cookieDomain,
    		String dominoSecret) {

        if (log.isDebugEnabled()) {

            StringBuilder obscuredDominoSecret = new StringBuilder();
            obscuredDominoSecret.append(dominoSecret.charAt(0));
            for (int i = 1; i < (dominoSecret.length() - 2); i++) {
                obscuredDominoSecret.append(".");
            }
            obscuredDominoSecret.append(dominoSecret.charAt(dominoSecret.length() -1));


            log.debug("Creating LtpaToken");
            log.debug(" Cookie name: " + cookieName);
            log.debug(" Cookie domain: " + cookieDomain);
            log.debug(" Domino secret: " + obscuredDominoSecret.toString());

        }

        init();
        ltpaToken = token;
        this.dominoSecret = dominoSecret;
        rawToken = Base64.decodeBase64(token);
        user = new byte[(rawToken.length) - 40];
        for (int i = 0; i < 4; i++) {
            header[i] = rawToken[i];
            log.debug("Header[" + i + "] = " + header[i]);
        }
        for (int i = 4; i < 12; i++) {
            creation[i - 4] = rawToken[i];
        }
        for (int i = 12; i < 20; i++) {
            expires[i - 12] = rawToken[i];
        }
        for (int i = 20; i < (rawToken.length - 20); i++) {
            user[i - 20] = rawToken[i];
        }
        for (int i = (rawToken.length - 20); i < rawToken.length; i++) {
            digest[i - (rawToken.length - 20)] = rawToken[i];
        }
        creationDate = new Date(Long.parseLong(new String(creation), 16) * 1000);
        expiresDate = new Date(Long.parseLong(new String(expires), 16) * 1000);
    }

    /**
     * Constructor for the LtpaToken object
     */
    private LtpaToken() {
        init();
    }

    public static Cookie newCookie(String sessionToken, String cookieName, String cookieDomain) {
        Cookie cookie = new Cookie(cookieName, sessionToken);

        cookie.setDomain(cookieDomain);
        cookie.setPath("/");
        cookie.setSecure(false);
        cookie.setMaxAge(-1);
        return cookie;
    }

    /**
     * Gets the creationDate attribute of the LtpaToken object
     * 
     * @return The creationDate value
     */
    public Date getCreationDate() {
        return creationDate;
    }

    /**
     * Gets the expiresDate attribute of the LtpaToken object
     * 
     * @return The expiresDate value
     */
    public Date getExpiresDate() {
        return expiresDate;
    }

    /**
     * Gets the user attribute of the LtpaToken object
     * 
     * @return The user value
     */
    public String getUser() {
        return new String(user);
    }

    /**
     * Validates the SHA-1 digest of the token with the Domino secret key.
     * 
     * @return Returns true if valid.
     */
    public boolean isValid() {
        boolean validDigest = false;
        boolean validDateRange = false;
        byte[] newDigest;
        byte[] bytes = null;
        Date now = new Date();

        log.debug("Getting MessageDigest");

        MessageDigest md = getDigest();

        log.debug("Concatenating header");

        bytes = concatenate(bytes, header);

        log.debug("Concatenating creation");

        bytes = concatenate(bytes, creation);

        log.debug("Concatenating expires");

        bytes = concatenate(bytes, expires);

        log.debug("Concatenating user");

        bytes = concatenate(bytes, user);

        log.debug("Concatenating secret");

        bytes = concatenate(bytes, Base64.decodeBase64(dominoSecret));

        log.debug("Digesting byte array");

        newDigest = md.digest(bytes);

        log.debug("Checking digest equality");

        validDigest = MessageDigest.isEqual(digest, newDigest);

        log.debug("Checking dates");

        validDateRange = now.after(creationDate) && now.before(expiresDate);

        log.debug("Valid digest: " + validDigest);
        log.debug(now + " is after " + creationDate + ": " + now.after(creationDate));
        log.debug(now + " is before " + expiresDate + ": " + now.before(expiresDate));
        log.debug("Valid date range: " + validDateRange);

        return validDigest & validDateRange;
    }

    /**
     * String representation of LtpaToken object.
     * 
     * @return Returns token String suitable for cookie value.
     */
    public String toString() {
        return ltpaToken;
    }

    /**
     * Creates a new SHA-1 <code>MessageDigest</code> instance.
     * 
     * @return The instance.
     */
    private MessageDigest getDigest() {
        try {
            return MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException nsae) {
            nsae.printStackTrace();
        }
        return null;
    }

    /**
     * Description of the Method
     */
    private void init() {

        creation = new byte[8];
        digest = new byte[20];
        expires = new byte[8];
        header = new byte[4];

    }

    /**
     * Validates the SHA-1 digest of the token with the Domino secret key.
     * 
     * @param ltpaToken
     *            Description of the Parameter
     * @return The valid value
     */
    public static boolean isValid(String ltpaToken, String cookieName,
    		String cookieDomain, String serverHostname, String dominoSecret) {
        LtpaToken ltpa = new LtpaToken(ltpaToken, cookieName, cookieDomain,
        		dominoSecret);
        return ltpa.isValid();
    }

    /**
     * Generates a new LtpaToken with given parameters.
     * 
     * @param canonicalUser
     *            User name in canonical form. e.g. 'CN=Robert Kelly/OU=MIS/O=EBIMED'.
     * @param tokenCreation
     *            Token creation date.
     * @param tokenExpires
     *            Token expiration date.
     * @return The generated token.
     */
    public static LtpaToken generate(String canonicalUser, Date tokenCreation, Date tokenExpires,
    		String cookieName, String cookieDomain, String dominoSecret) {
  
        LtpaToken ltpa = new LtpaToken();
        log.debug("Generating token for " + canonicalUser);
        Calendar calendar = Calendar.getInstance();
        MessageDigest md = ltpa.getDigest();
        ltpa.header = new byte[] { 0, 1, 2, 3 };
        ltpa.user = canonicalUser.getBytes();
        byte[] token = null;
        calendar.setTime(tokenCreation);
        ltpa.creation = Long.toHexString(calendar.getTimeInMillis() / 1000).toUpperCase().getBytes();
        calendar.setTime(tokenExpires);
        ltpa.expires = Long.toHexString(calendar.getTimeInMillis() / 1000).toUpperCase().getBytes();
        ltpa.user = canonicalUser.getBytes();
        token = concatenate(token, ltpa.header);
        token = concatenate(token, ltpa.creation);
        token = concatenate(token, ltpa.expires);
        token = concatenate(token, ltpa.user);
        md.update(token);

		log.debug("Token without digest: [" + token + "]");
        ltpa.digest = md.digest(Base64.decodeBase64(dominoSecret));
        token = concatenate(token, ltpa.digest);
        log.debug("Token with digest: [" + token + "]");
		String base64encodedToken = Base64.encodeBase64String(token);
        log.debug("Base64-encoded token: [" + base64encodedToken + "]");

        return new LtpaToken(base64encodedToken, cookieName,
        		cookieDomain, dominoSecret);
    }

    /**
     * Helper method to concatenate a byte array.
     * 
     * @param a
     *            Byte array a.
     * @param b
     *            Byte array b.
     * @return a + b.
     */
    private static byte[] concatenate(byte[] a, byte[] b) {
        if (a == null) {
            return b;
        } else {
            byte[] bytes = new byte[a.length + b.length];

            System.arraycopy(a, 0, bytes, 0, a.length);
            System.arraycopy(b, 0, bytes, a.length, b.length);
            return bytes;
        }
    }

    public String getLtpaToken() {
    	if(ltpaToken != null) {
    		return ltpaToken.trim();
    	} else {
    		return null;
    	}
    }

    public void setLtpaToken(String ltpaToken) {
        this.ltpaToken = ltpaToken;
    }
}
