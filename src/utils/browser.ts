/*
 *   Copyright (c) 2024 LoginID Inc
 *   All rights reserved.

 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at

 *   http://www.apache.org/licenses/LICENSE-2.0

 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

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
