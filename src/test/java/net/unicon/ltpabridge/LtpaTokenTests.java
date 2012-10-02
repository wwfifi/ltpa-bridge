package net.unicon.ltpabridge;

import com.sun.servicetag.SystemEnvironment;
import junit.framework.TestCase;
import org.junit.Test;

import org.apache.commons.codec.binary.Base64;

import java.util.Date;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 *
 */
public class LtpaTokenTests {
    
    private static String cookieName = "LtpaToken";
    private static String domain = ".example.edu";
    private static String dominoSecret = "jcDWR0+4RXCEZyLRb8a1zvATUQA=";

  @Test
  public void testCreateTokenShortUsername() {

      Date creationDate = new Date();
      Date expirationDate = new Date();
      expirationDate.setTime(System.currentTimeMillis() + 2000000);
      
      testTokenWithUsername("shortUsername", creationDate, expirationDate);
      
  }
    
  @Test
  public void testCreateTokenSeventeenCharacterUsername() {

      // need known dates so that token is always the same so can test against regressions.

      Date creationDate = new Date();
      creationDate.setTime(314168400000L); // December 16 1979

      Date expirationDate = new Date();
      expirationDate.setTime(1605762000000L); // November 19 2020


      LtpaToken token = testTokenWithUsername("seventeenCharctrs", creationDate, expirationDate);

      assertEquals("Token should have matched expected encoded String",
              "AAECAzEyQjlENDUwNUZCNUZCRDBzZXZlbnRlZW5DaGFyY3RycyhoK2o/Wu+1Uwcf0T/InzBZ8bRd",
              token.getLtpaToken());

  }
    
  @Test
  public void testCreateTokenEighteenCharacterUsername() {

      Date creationDate = new Date();
      Date expirationDate = new Date();
      expirationDate.setTime(System.currentTimeMillis() + 2000000);

      testTokenWithUsername("eighteenCharacters", creationDate, expirationDate);
  }


  @Test
  public void testCreateTokenReallyLongUsername() {

      Date creationDate = new Date();
      Date expirationDate = new Date();
      expirationDate.setTime(System.currentTimeMillis() + 2000000);

      testTokenWithUsername("egregiouslyReallyUnreasonablyLongUsernameWhyIsItSoLongTheresNoGoodReasonForThisReally",
              creationDate, expirationDate);

  }

  @Test
  public void testManyUsernames(){

      String[] usernames = {
              "1",
              "10",
              "011",
              "four",
              "fiver",
              "sixsix",
              "6seven8",
              "jollynine",
              "tendixdeca",
              "elevenbmore",
              "twelvemonths",
              "luckythirteen",
              "fourteen141414",
              "fifteencinquant",
              "sixteensixteensi",
              "seventeenseventy6",
              "eighteenloremipsum",
              "nineteeneightyseven",
              "twentienthcenturyfox",
              "twentyfirstcenturyfox",
              "twentytwocharactersbig",
              "twentythreecharactersis",
              "twentyfouralsoworksswell",
              "twentyfivecharacterslong!",
              "thisisgettingsillyverysill",
      };


      for (String username : usernames) {
          Date creationDate = new Date();
          Date expirationDate = new Date();
          expirationDate.setTime(System.currentTimeMillis() + 2000000);

          testTokenWithUsername(username,
                  creationDate, expirationDate);
      }
  }
    

  public LtpaToken testTokenWithUsername(String username, Date creationDate, Date expirationDate) {
      System.out.println("Testing for username [" + username + "], which has " + username.length() + " characters");


      LtpaToken ltpaToken = LtpaToken.generate(username, creationDate, expirationDate,
              cookieName, domain, dominoSecret);

      assertTrue("Token should have been valid, but wasn't.", ltpaToken.isValid());
      
      System.out.println("Encoded token:");
      System.out.println(ltpaToken);
      System.out.println("Decoded token:");
      System.out.println(Base64.decodeBase64(ltpaToken.toString()));
      
      


      // demonstrate going from a token string to the values

      String ltpaTokenString = ltpaToken.getLtpaToken();

      LtpaToken generatedFromString = new LtpaToken(ltpaTokenString, cookieName, domain, dominoSecret);
      String recoveredUsername = generatedFromString.getUser();

      assertEquals(recoveredUsername, username);
      //assertEquals(generatedFromString.getCreationDate(), creationDate);
      //assertEquals(generatedFromString.getExpiresDate(), expirationDate);

      assertTrue(generatedFromString.isValid());

      System.out.println("Recovered token:");
      System.out.println(generatedFromString);
      System.out.println("Recovered token decoded:");
      System.out.println(Base64.decodeBase64(generatedFromString.toString()));

      assertFalse("Tokens should not contain ' '", ltpaToken.getLtpaToken().contains(" "));
      assertFalse("Tokens should not contain '\\n'", ltpaToken.getLtpaToken().contains("\n"));
      assertFalse("Tokens should not contain '\\r'", ltpaToken.getLtpaToken().contains("\r"));

      return ltpaToken;
  }

}
