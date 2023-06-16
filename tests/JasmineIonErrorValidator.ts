import IonError from '../lib/IonError.js';

/**
 * Encapsulates the helper functions for the tests.
 */
export default class JasmineIonErrorValidator {
  /**
   * Fails the current spec if the execution of the function does not throw the expected IonError.
   *
   * @param functionToExecute The function to execute.
   * @param expectedErrorCode The expected error code.
   */
  public static expectIonErrorToBeThrown (functionToExecute: () => any, expectedErrorCode: string): void {
    let validated: boolean = false;

    try {
      functionToExecute();
    } catch (e) {
      if (e instanceof IonError) {
        expect(e.code).toEqual(expectedErrorCode);
        validated = true;
      }
    }

    if (!validated) {
      fail(`Expected error '${expectedErrorCode}' did not occur.`);
    }
  }

  /**
   * Fails the current spec if the execution of the function does not throw the expected IonError.
   *
   * @param functionToExecute The function to execute.
   * @param expectedErrorCode The expected error code.
   */
  public static async expectIonErrorToBeThrownAsync (functionToExecute: () => Promise<any>, expectedErrorCode: string): Promise<void> {
    let validated: boolean = false;

    try {
      await functionToExecute();
    } catch (e: any) {
      if (e instanceof IonError) {
        expect(e.code).toEqual(expectedErrorCode);
        validated = true;
      }
    }

    if (!validated) {
      fail(`Expected error '${expectedErrorCode}' did not occur.`);
    }
  }
}
