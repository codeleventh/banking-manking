package ru.eleventh;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Locale;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Main {

  public final String getMd5Hash(String input) {
    try {
      MessageDigest messageDigest = MessageDigest.getInstance("MD5");
      byte[] bytes = input.getBytes();
      String bigInteger = new BigInteger(1, messageDigest.digest(bytes)).toString(16);
//      return StringsKt.padStart(bigInteger, 32, '0');
      return bigInteger;
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      return "";
    }
  }

  private String getCurrentTime(LocalDateTime dateTime) {
    // String dateTime = DateTime.now(DateTimeZone.UTC).toString(DateTimeFormat.forPattern(DateUtilsKt.REQUEST_DATETIME).withZoneUTC().withLocale(Locale.US));
    ZoneId zoneId = ZoneOffset.UTC;
    ZonedDateTime zonedDateTime = dateTime.atZone(zoneId);
    return zonedDateTime.format(
        DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'").withZone(zoneId)
            .withLocale(Locale.US));
  }

  private String generateKey(String confirmationCode, String accessSecret) {
    var i = 0;
    var i2 = 0;
    var i3 = 12;
    Object obj = null;
    if ((i3 & 4) != 0) {
      i = 1000;
    }
    if ((i3 & 8) != 0) {
      i2 = 20;
    }
    return cryptoKotlinGenerateKey(confirmationCode, accessSecret, i, i2);
  }

  public final String cryptoKotlinGenerateKey(String password, String accessSecret, int iterations,
      int keyLength) {
    try {
      byte[] decode = Base64.getDecoder().decode(accessSecret.getBytes());
      SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
      char[] charArray = password.toCharArray();
      var secretKey = secretKeyFactory.generateSecret(
          new PBEKeySpec(charArray, decode, iterations, keyLength * 8)).getEncoded();
      return new String(Base64.getEncoder().withoutPadding().encode(secretKey));
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }

  /***
   *
   * @param verb - HTTP method
   * @param body - json body
   * @param urlPath - url path TODO:
   * @param key - encrypted confirmation code {@see Main.generateKey}
   * @param accessKeyId - user accessKeyId
   * @param currentTime - {@see Main.getCurrentTime} TODO:
   * @return
   */
  public final String generateAuthHeader(String verb, String body, String urlPath, String key,
      String accessKeyId, String currentTime) {
    try {
      String str =
          verb + '\n' + getMd5Hash(body) + "\napplication/x-www-form-urlencoded; charset=utf-8\n"
              + currentTime + "\n\n" + urlPath.substring(1);
      Mac mac = Mac.getInstance("HmacSHA1");
      mac.init(new SecretKeySpec(Base64.getDecoder().decode(key), mac.getAlgorithm()));
      byte[] bytes = str.getBytes();
      byte[] encode = Base64.getEncoder().encode(key.getBytes());
      return "PWS " + accessKeyId + ':' + new String(encode).trim();
    } catch (Exception e) {
      e.printStackTrace();
      return "";
    }
  }

  public String test(String request, String accessKeyId, String accessSecret, String accessCode,
      LocalDateTime now) {
//    var headers = Arrays.stream(request.substring(0, request.indexOf("\n\n")).split("\n")).skip(1)
//        .collect(Collectors.toMap(s -> s.split(": ?")[0], s -> s.split(": ?")[1]));
    var body = java.net.URLDecoder.decode(request.substring(request.indexOf("\n\n") + 2));
    var verb = request.substring(0, request.indexOf(" "));
    var urlPath = request.substring(request.indexOf(" ") + 1, request.indexOf("\n"));
    var key = generateKey(accessCode, accessSecret);
    return generateAuthHeader(verb, body, urlPath, key, accessKeyId, getCurrentTime(now));
  }

  public static void main(String[] args) {
    var main = new Main();
    var request = "POST /clients/history HTTP/1.1\n"
        + "Host: telcellmoney.am\n"
        + "Accept: */*\n"
        + "Authorization: PWS a583977a721a499fa6698a2f19d3e418:OMqlGYDgXIcPpgj7nXWye0XbIAw=\n"
        + "X-DT-Country: \n"
        + "Content-MD5: 215247dd25b5202c0b4033dac4477800\n"
        + "X-DT-Client-Version: 1.5.0\n"
        + "Accept-Language: ru\n"
        + "Accept-Encoding: gzip, deflate, br\n"
        + "Date: Thu, 03 Oct 2024 19:12:21 GMT\n"
        + "X-DT-Version: 6.0\n"
        + "Content-Length: 67\n"
        + "User-Agent: agent 9b0a3d08ec3d3bad96ecb6ef379979a6\n"
        + "Connection: keep-alive\n"
        + "Content-Type: application/x-www-form-urlencoded\n"
        + "\n"
        + "data=%7B%22pageSize%22:20,%22lang%22:%22ru%22,%22pageNumber%22:0%7D";
    var accessKeyId = "a583977a721a499fa6698a2f19d3e418";
    var accessSecret = "MmIxNTYwNDljOTJjNDQ1MzlmNjE1YTkyNDRjNTYwZTU=";
    var confirmationCode = "8800";
    var now = LocalDateTime.now();
    // another example: var now = LocalDateTime.of(1970, 1,1, 0,0,0);
    System.out.println(main.test(request, accessKeyId, accessSecret, confirmationCode, now));
  }
}