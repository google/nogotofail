/*
 * Copyright 2012 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.nogotofail;

/**
 * Hexadecimal encoding where each byte is represented by two hexadecimal digits.
 */
public final class HexEncoding {
  private HexEncoding() {}

  private static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();

  /**
   * Encodes the provided data as a hexadecimal string.
   */
  public static String encode(byte[] data, int offset, int len) {
    StringBuilder result = new StringBuilder(len * 2);
    for (int i = 0; i < len; i++) {
      byte b = data[offset + i];
      result.append(HEX_DIGITS[(b >>> 4) & 0x0f]);
      result.append(HEX_DIGITS[b & 0x0f]);
    }
    return result.toString();
  }

  /**
   * Encodes the provided data as a hexadecimal string.
   */
  public static String encode(byte[] data) {
    return encode(data, 0, data.length);
  }


  /**
   * Decodes the provided hexadecimal string into an array of bytes.
   */
  public static byte[] decode(String encoded) {
    // IMPLEMENTATION NOTE: Special care is taken to permit odd number of hexadecimal digits.
    int resultLengthBytes = (encoded.length() + 1) / 2;
    byte[] result = new byte[resultLengthBytes];
    int resultOffset = 0;
    int encodedCharOffset = 0;
    if ((encoded.length() % 2) != 0) {
      // Odd number of digits -- the first digit is the lower 4 bits of the first result byte.
      result[resultOffset++] = (byte) getHexadecimalDigitValue(encoded.charAt(encodedCharOffset));
      encodedCharOffset++;
    }
    for (int len = encoded.length(); encodedCharOffset < len; encodedCharOffset += 2) {
      result[resultOffset++] = (byte)
          ((getHexadecimalDigitValue(encoded.charAt(encodedCharOffset)) << 4)
          | getHexadecimalDigitValue(encoded.charAt(encodedCharOffset + 1)));
    }
    return result;
  }

  private static int getHexadecimalDigitValue(char c) {
    if ((c >= 'a') && (c <= 'f')) {
      return (c - 'a') + 0x0a;
    } else if ((c >= 'A') && (c <= 'F')) {
      return (c - 'A') + 0x0a;
    } else if ((c >= '0') && (c <= '9')) {
      return c - '0';
    } else {
      throw new IllegalArgumentException(
          "Invalid hexadecimal digit at position : '" + c + "' (0x" + Integer.toHexString(c) + ")");
    }
  }
}
