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
  static expectIonErrorToBeThrown(functionToExecute: () => any, expectedErrorCode: string): void;
  /**
     * Fails the current spec if the execution of the function does not throw the expected IonError.
     *
     * @param functionToExecute The function to execute.
     * @param expectedErrorCode The expected error code.
     */
  static expectIonErrorToBeThrownAsync(functionToExecute: () => Promise<any>, expectedErrorCode: string): Promise<void>;
}
