const canonicalize = require('canonicalize');

/**
 * Class containing reusable JSON canonicalization operations using JSON Canonicalization Scheme (JCS).
 */
export default class JsonCanonicalizer {
  /**
   * Canonicalizes the given content as a UTF8 buffer.
   */
  public static canonicalizeAsBuffer (content: object): Buffer {
    // We need to remove all properties with `undefined` as value so that JCS canonicalization will not produce invalid JSON.
    const contentWithoutUndefinedProperties = JsonCanonicalizer.removeAllUndefinedProperties(content);
    const canonicalizedString: string = canonicalize(contentWithoutUndefinedProperties);
    const contentBuffer = Buffer.from(canonicalizedString);
    return contentBuffer;
  }

  /**
   * Removes all properties within the given object with `undefined` as value.
   */
  private static removeAllUndefinedProperties (content: any): any {
    for (const key in content) {
      if (typeof content[key] === 'object') {
        JsonCanonicalizer.removeAllUndefinedProperties(content[key]);
      } else if (content[key] === undefined) {
        delete content[key];
      }
    }

    return content;
  }
}
