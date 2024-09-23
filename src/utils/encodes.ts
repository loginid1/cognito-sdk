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

import {LoginIDAccessJWT} from './types'

/**
 * Parses the JWT token and returns the payload.
 *
 * @param {string} token - The JWT token to parse.
 * @returns {LoginIDAccessJWT} - The payload of the JWT token.
 */
export function parseJwt(token: string): LoginIDAccessJWT {
  try {
    const parts = token.split('.')
    return JSON.parse(atob(parts[1]))
  } catch {
    throw new Error('Invalid JWT token')
  }
}
