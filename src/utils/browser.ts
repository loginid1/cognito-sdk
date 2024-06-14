import {DeviceInfo} from './types'

/**
 * Retrieves default device information based on the user agent for LoginID service (gen3).
 * This function parses the user agent string to extract information about the client,
 * such as browser name, version, operating system, and architecture.
 * It constructs a deviceInfoRequestBody object containing this information and returns it.
 */
export const defaultDeviceInfo = (): DeviceInfo => {
  const device: DeviceInfo = {
    clientType: 'browser',
    screenWidth: window.screen.width,
    screenHeight: window.screen.height,
  }

  return device
}

/**
 * Retrieves the user agent string from the browser.
 */ 
export const getUserAgent = (): string => {
  return window.navigator.userAgent
}
