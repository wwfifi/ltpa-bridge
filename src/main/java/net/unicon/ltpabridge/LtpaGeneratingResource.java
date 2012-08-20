package net.unicon.ltpabridge;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.WebResource;
import org.apache.shiro.cas.CasRealm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.Date;

/**
 * An HTTP resource protected by an authentication mechanism and acting as an external bridge to generate LTPA tokens based on authenticated principals,
 * encode those tokens into an HTTP Cookie header and redirect requests to a pre-configured HTTP resource that knows how to handle LTPA tokens for further processing.
 * <p/>
 * This implementation makes no assumption of the actual authentication mechanism that it is being protected by nor any specific details about LTPA processing destination
 * resource other than its pre-configured URI.
 *
 * @author Dmitriy Kopylenko
 * @author Unicon, inc.
 * @since 1.0
 */

@Component
@Path("/token")
public class LtpaGeneratingResource {

	@Context
	private HttpServletRequest request;

	@Context
	private HttpServletResponse response;

	@Value("${ltpa.cookie.name}")
	private String ltpaCookieName;

	@Value("${ltpa.cookie.domain}")
	private String ltpaCookieDomain;

	@Value("${ltpa.cookie.path}")
	private String ltpaCookiePath;

	@Value("${ltpa.cookie.secure}")
	private boolean ltpaCookieSecure;

	@Value("${ltpa.token.expiration}")
	private int ltpaTokenExpirationInMinutes;

	@Value("${ltpa.token.clockskew}")
	private int ltpaTokenClockSkewInSeconds;

	@Value("${ltpa.domino.secret}")
	private String ltpaDominoSeceret;

	@Value("${ltpa.domino.service}")
	private String ltpaDestinationResourceUri;

	@GET
	public Response generateLtpaToken() throws IOException {
		String subject = this.request.getRemoteUser();

		Date creation = new Date();
		creation.setTime(creation.getTime() - this.ltpaTokenClockSkewInSeconds);
		Date expiration = new Date();
		expiration.setTime(expiration.getTime() + this.ltpaTokenExpirationInMinutes + this.ltpaTokenClockSkewInSeconds);

		LtpaToken ltpaToken = LtpaToken.generate(subject, creation, expiration, this.ltpaCookieName, this.ltpaCookieDomain, this.ltpaDominoSeceret);

		Cookie ltpaCookie = new Cookie(this.ltpaCookieName, ltpaToken.getLtpaToken());
		ltpaCookie.setDomain(this.ltpaCookieDomain);
		ltpaCookie.setPath(this.ltpaCookiePath);
		ltpaCookie.setSecure(this.ltpaCookieSecure);

		addCookieToResponse(this.response, ltpaCookie);
		this.response.sendRedirect(this.ltpaDestinationResourceUri);

		//HTTP 204
		return Response.noContent().build();
	}

	private void addCookieToResponse(HttpServletResponse response, Cookie cookie) {
		if (cookie.getName() == null || cookie.getValue() == null) {
			return;
		}

		StringBuffer buf = new StringBuffer();
		buf.append(cookie.getName());
		buf.append("=");
		buf.append(cookie.getValue());

		if (cookie.getDomain() != null && !("").equals(cookie.getDomain())) {
			buf.append("; Domain=");
			buf.append(cookie.getDomain());
		}
		if (cookie.getPath() != null && !("").equals(cookie.getPath())) {
			buf.append("; Path=");
			buf.append(cookie.getPath());
		}
		if (cookie.getSecure()) {
			buf.append("; Secure");
		}
		String cookieString = buf.toString();
		response.addHeader("Set-Cookie", cookieString);
	}
}
