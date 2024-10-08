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

import { LoginIDAPI, WebAuthnHelper } from '@loginid/websdk3'
import LoginIDService from '../services/loginid'
import { defaultDeviceInfo, getUserAgent } from '../utils/browser'
import { AuthResult, CustomAuthenticationOptions, InnerOptions } from './types'
import {
  AuthenticationDetails,
  CognitoUser,
  CognitoUserAttribute,
  CognitoUserPool,
  CognitoUserSession,
  IAuthenticationCallback,
  IAuthenticationDetailsData,
  ICognitoUserData,
} from 'amazon-cognito-identity-js'
import { LoginidAPIError } from '../errors'

/**
 * Enumeration representing different types of custom authentication operations.
 */
export enum CustomAuthentication {
  ACCESS_JWT = 'JWT_ACCESS',
  EMAIL_OTP = 'EMAIL_OTP',
  AUTH_PARAMS = 'AUTH_PARAMS',
  FIDO2_CREATE = 'FIDO2_CREATE',
  FIDO2_GET = 'FIDO2_GET',
}

/**
 * Cognito class for custom authentication using FIDO2.
 */
class Cognito {
  private userPool: CognitoUserPool
  private lidService: LoginIDService

  /**
   * Constructor for the Cognito class.
   *
   * @param {string} userPoolId - The ID of the Cognito User Pool.
   * @param {string} clientId - The client ID associated with the User Pool.
   */
  constructor(service: LoginIDService, userPoolId: string, clientId: string) {
    this.lidService = service
    this.userPool = new CognitoUserPool({
      UserPoolId: userPoolId,
      ClientId: clientId,
    })
  }

  /**
   * Performs custom authentication using FIDO2 for either create or get operations.
   *
   * @param {string} username - The username of the Cognito user.
   * @param {string} token - The token associated with the user.
   * @param {CustomAuthentication} type - The type of custom authentication operation (FIDO2_CREATE or FIDO2_GET).
   * @param {CustomAuthenticationOptions} options - Additional options for custom authentication.
   * @param {object} options.metaData - Additional metadata for the authentication process.
   * @param {AttestationOptions} options.attestationOptions - Attestation options for FIDO2 operations.
   * @returns {Promise<CognitoUserSession>} - A promise resolving to the Cognito user session.
   */
  public async customAuthenticationPasskey(
    username: string,
    token: string,
    type: CustomAuthentication,
    options: CustomAuthenticationOptions,
  ): Promise<AuthResult> {
    return new Promise((resolve, reject) => {
      const lidService = this.lidService

      const lowerUsername = username.toLowerCase()
      const authenticationData: IAuthenticationDetailsData = {
        Username: lowerUsername,
        Password: '',
      }
      const userData: ICognitoUserData = {
        Username: lowerUsername,
        Pool: this.userPool,
      }

      const authenticationDetails = new AuthenticationDetails(authenticationData)
      const user = new CognitoUser(userData)

      const metaData = options.metaData || {}
      const fullOptions: InnerOptions = {
        idToken: token,
        deviceInfo: defaultDeviceInfo(),
        userAgent: getUserAgent(),
        user: {
          ...options.displayName && { displayName: options.displayName },
          ...options.usernameType && { usernameType: options.usernameType },
        }
      }

      // Callback object for FIDO2_CREATE operation
      const callbackCreateObj: IAuthenticationCallback = {
        customChallenge: async function (challengParams: any) {
          const clientMetadata = {
            ...metaData,
            options: JSON.stringify(fullOptions),
            authentication_type: CustomAuthentication.FIDO2_CREATE,
          }

          if (challengParams?.challenge === CustomAuthentication.AUTH_PARAMS) {
            user.sendCustomChallengeAnswer(
              CustomAuthentication.AUTH_PARAMS,
              this,
              clientMetadata
            )
            return
          }

          const init = JSON.parse(challengParams.public_key)
          if (options.abortController && !options.abortController.signal.aborted) {
            // abort current controller to allow new passkey creation
            options.abortController.abort()
          }
          //const publicKey = await lid.createNavigatorCredential(init)
          const publicKey = await WebAuthnHelper.createNavigatorCredential(init)
          const { jwtAccess, deviceID } = await lidService.passkeyRegComplete(publicKey)
          // store trusted deviceID
          if (deviceID) {
            lidService.saveTrustedDevice(username, deviceID)
          }

          //lid.setJwtCookie(jwtAccess)

          user.sendCustomChallengeAnswer(
            jwtAccess,
            this,
            clientMetadata
          )
        },

        onSuccess: function (session: CognitoUserSession) {
          const aresult: AuthResult = {
            idToken: session.getIdToken().getJwtToken(),
            accessToken: session.getAccessToken().getJwtToken(),
            refreshToken: session.getRefreshToken().getToken(),
            isAuthenticated: true,
            isFallback: false,
          }
          resolve(aresult)
        },

        onFailure: function (err) {
          reject(err)
        },
      }


      // Callback object for FIDO2_GET operation
      const callbackGetObj: IAuthenticationCallback = {
        customChallenge: async function () {
          const clientMetadata = {
            ...metaData,
            options: JSON.stringify(fullOptions),
            authentication_type: CustomAuthentication.FIDO2_GET,
          }


          const auth_init_request = <LoginIDAPI.AuthInitRequestBody>{
            app: { id: lidService.getAppId() },
            user: { username: username, usernameType: 'email' },
            deviceInfo: lidService.getDeviceInfo(username),
          }

          try {

            const auth_init_result = await lidService.passkeyAuthInit(auth_init_request)
            //const match_threshold = options.matchThreshold || DEFAULT_MATCH_THRESHOLD
            const hasAutofill = lidService.getHasAutofill(username)

            if (!hasAutofill && auth_init_result.action !== 'proceed') {
              const aresult: AuthResult = {
                idToken: '',
                accessToken: '',
                isAuthenticated: false,
                isFallback: true,
                fallbackOptions: auth_init_result.fallbackMethods
              }
              resolve(aresult)

            } else {
              if (options.abortController && !options.abortController.signal.aborted) {
                // abort current controller to allow new passkey creation
                options.abortController.abort()
                console.log('abort webauthn get')
              }

              const webauthn_result = await WebAuthnHelper.getNavigatorCredential(auth_init_result)
              //const webauthn_result = await lid.getNavigatorCredential(auth_init_result)
              const jwt = await lidService.passkeyAuthComplete(webauthn_result)

              user.sendCustomChallengeAnswer(
                //JSON.stringify({ ...result }),
                jwt.jwtAccess,
                this,
                clientMetadata
              )

            }
          } catch (e) {
            if (e instanceof LoginidAPIError) {
              if (e.msgCode === 'not_found') {
                reject(new LoginidAPIError('no passkey detected', 'ERROR_FALLBACK'))
              }
            }

          }


        },

        onSuccess: function (session: CognitoUserSession) {
          const aresult: AuthResult = {
            idToken: session.getIdToken().getJwtToken(),
            accessToken: session.getAccessToken().getJwtToken(),
            refreshToken: session.getRefreshToken().getToken(),
            isAuthenticated: true,
            isFallback: false,
          }
          resolve(aresult)
        },

        onFailure: function (err) {
          reject(err)
        },
      }

      // Callback object for ACCESS_JWT operation
      const callbackJWTObj: IAuthenticationCallback = {
        customChallenge: function () {
          const clientMetadata = {
            ...metaData,
            options: JSON.stringify(fullOptions),
            authentication_type: CustomAuthentication.ACCESS_JWT,
          }
          user.sendCustomChallengeAnswer(
            token,
            this,
            clientMetadata
          )
        },

        onSuccess: function (session: CognitoUserSession) {
          const aresult: AuthResult = {
            idToken: session.getIdToken().getJwtToken(),
            accessToken: session.getAccessToken().getJwtToken(),
            refreshToken: session.getRefreshToken().getToken(),
            isAuthenticated: true,
            isFallback: false,
          }
          resolve(aresult)
        },

        onFailure: function (err) {
          reject(err)
        },
      }

      // Initiating custom authentication based on the specified type
      switch (type) {
        case CustomAuthentication.FIDO2_CREATE:
          user.setAuthenticationFlowType('CUSTOM_AUTH')
          user.initiateAuth(authenticationDetails, callbackCreateObj)
          break

        case CustomAuthentication.FIDO2_GET:
          user.setAuthenticationFlowType('CUSTOM_AUTH')
          user.initiateAuth(authenticationDetails, callbackGetObj)
          break

        case CustomAuthentication.ACCESS_JWT:
          user.setAuthenticationFlowType('CUSTOM_AUTH')
          user.initiateAuth(authenticationDetails, callbackJWTObj)
          break

        default:
          throw new Error('Invalid custom authentication type')
      }
    })
  }

  /**
   * Initiates custom authentication for the specified username.
   *
   * @param {string} username - The username of the Cognito user.
   * @param {CustomAuthentication} type - The type of custom authentication operation (FIDO2_CREATE or FIDO2_GET).
   * @param {CustomAuthenticationOptions} options - Additional options for custom authentication.
   * @returns {Promise<CognitoUser>} - A promise resolving to the Cognito user.
   */
  public async customAuthenticationInit(
    username: string,
    type: CustomAuthentication,
    options: CustomAuthenticationOptions,
  ): Promise<CognitoUser> {
    return new Promise((resolve, reject) => {
      const lowerUsername = username.toLowerCase()
      const authenticationData: IAuthenticationDetailsData = {
        Username: lowerUsername,
        Password: '',
      }
      const userData: ICognitoUserData = {
        Username: lowerUsername,
        Pool: this.userPool,
      }

      const authenticationDetails = new AuthenticationDetails(authenticationData)
      const user = new CognitoUser(userData)

      const metaData = options.metaData || {}

      // Callback object for ACCESS_JWT operation
      const callbackEmailOTP: IAuthenticationCallback = {
        customChallenge: function (challengParams: any) {
          const clientMetadata = {
            ...metaData,
            authentication_type: CustomAuthentication.EMAIL_OTP,
          }

          if (challengParams?.challenge === CustomAuthentication.AUTH_PARAMS) {
            user.sendCustomChallengeAnswer(
              CustomAuthentication.AUTH_PARAMS,
              this,
              clientMetadata
            )
            return
          } else if (challengParams?.challenge === CustomAuthentication.EMAIL_OTP) {
            resolve(user)
          } else {
            reject(new Error('Invalid custom challenge'))
          }
        },

        onSuccess: function () {
          // Should never reach here but need to satisfy the interface
          resolve(user)
        },

        onFailure: function (err) {
          reject(err)
        },
      }

      // Initiating custom authentication based on the specified type
      switch (type) {
        case CustomAuthentication.EMAIL_OTP:
          user.setAuthenticationFlowType('CUSTOM_AUTH')
          user.initiateAuth(authenticationDetails, callbackEmailOTP)
          break

        default:
          throw new Error('Invalid custom authentication type')
      }
    })
  }

  /**
   * Responds to custom authentication challenge for the given username.
   *
   * @param {string} username - The username of the Cognito user.
   * @param {CustomAuthentication} type - The type of custom authentication operation (FIDO2_CREATE or FIDO2_GET).
   * @param {CustomAuthenticationOptions} options - Additional options for custom authentication.
   * @returns {Promise<CognitoUser>} - A promise resolving to the Cognito user.
   */
  public async customAuthenticationComplete(
    user: CognitoUser,
    answer: string,
    type: CustomAuthentication,
    options: CustomAuthenticationOptions,
  ): Promise<AuthResult> {
    return new Promise((resolve, reject) => {
      const metaData = options.metaData || {}
      const clientMetadata = {
        ...metaData,
        authentication_type: type,
      }

      const callbackObj: IAuthenticationCallback = {
        customChallenge: async function () {
          console.log('Retry...')
          reject(new LoginidAPIError('error - please retry'))
        },

        onSuccess: function (session: CognitoUserSession) {
          const aresult: AuthResult = {
            idToken: session.getIdToken().getJwtToken(),
            accessToken: session.getAccessToken().getJwtToken(),
            refreshToken: session.getRefreshToken().getToken(),
            isAuthenticated: true,
            isFallback: false,
          }
          resolve(aresult)
        },

        onFailure: function (err) {
          reject(err)
        },
      }

      user.setAuthenticationFlowType('CUSTOM_AUTH')
      user.sendCustomChallengeAnswer(
        answer,
        callbackObj,
        clientMetadata
      )
    })
  }

  public async signUp(email: string, password: string, autoSignIn: boolean): Promise<AuthResult> {

    return new Promise((resolve, reject) => {

      const lowerEmail = email.toLowerCase()
      const attributeList = []
      const dataEmail = {
        Name: 'email',
        Value: lowerEmail,
      }

      const attributeEmail = new CognitoUserAttribute(dataEmail)

      attributeList.push(attributeEmail)

      this.userPool.signUp(
        lowerEmail,
        password,
        attributeList,
        [],
        function (err, result) {
          if (err) {
            reject(new Error(err.message))
            return
          }
          if (result != null) {

            if (autoSignIn) {
              const authenticationData = {
                Username: lowerEmail,
                Password: password,
              }
              const authenticationDetails = new AuthenticationDetails(
                authenticationData
              )
              result.user.authenticateUser(authenticationDetails, {
                onSuccess: function (session: CognitoUserSession) {

                  const aresult: AuthResult = {
                    idToken: session.getIdToken().getJwtToken(),
                    accessToken: session.getAccessToken().getJwtToken(),
                    refreshToken: session.getRefreshToken().getToken(),
                    isAuthenticated: true,
                    isFallback: false,
                  }
                  resolve(aresult)
                },

                onFailure: function (autoSigninError) {
                  reject(autoSigninError)
                },
              })
            } else {

              const aresult: AuthResult = {
                idToken: '',
                accessToken: '',
                isAuthenticated: false,
                isFallback: false,
              }

              resolve(aresult)

            }
          } else {
            reject(new Error('error empty result'))
          }
        }
      )

    })
  }

  public async signInPassword(email: string, password: string): Promise<CognitoUserSession> {

    return new Promise((resolve, reject) => {
      const lowerEmail = email.toLowerCase()
      const authenticationData = {
        Username: lowerEmail,
        Password: password,
      }
      const authenticationDetails = new AuthenticationDetails(
        authenticationData
      )

      const userData: ICognitoUserData = {
        Username: lowerEmail,
        Pool: this.userPool,
      }

      const user = new CognitoUser(userData)
      user.authenticateUser(authenticationDetails, {
        onSuccess: function (session: CognitoUserSession) {
          resolve(session)
        },

        onFailure: function (autoSigninError) {
          reject(autoSigninError)
        },
      })
    })

  }

  public signOut() {
    const user = this.userPool.getCurrentUser()
    if (user != null) {
      user.signOut()
    }
  }

  public currentUsername(): string | null {
    const user = this.userPool.getCurrentUser()
    if (user) {
      return user.getUsername()
    }
    return null
  }

  public getCurrentCognitoIdToken(): string | null {

    const user = this.userPool.getCurrentUser()
    if (user && window) {
      const key = 'CognitoIdentityServiceProvider.' + this.userPool.getClientId() + '.' + user.getUsername() + '.idToken'
      const token = localStorage.getItem(key)
      return token
    }
    return null
  }

  public getCurrentCognitoAccessToken(): string | null {

    const user = this.userPool.getCurrentUser()
    if (user && window) {
      const key = 'CognitoIdentityServiceProvider.' + this.userPool.getClientId() + '.' + user.getUsername() + '.accessToken'
      const token = localStorage.getItem(key)
      return token
    }
    return null
  }
}

export type { CustomAuthenticationOptions }

export default Cognito
