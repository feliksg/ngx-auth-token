import { Injectable, Optional } from '@angular/core';
import { ActivatedRoute, Router, CanActivate, CanActivateChild } from '@angular/router';
import { HttpClient, HttpHeaders } from '@angular/common/http';

import { Observable } from 'rxjs/Observable';
import 'rxjs/add/operator/share';
import 'rxjs/add/observable/interval';
import 'rxjs/add/observable/fromEvent';
import 'rxjs/add/operator/pluck';
import 'rxjs/add/operator/filter';
import 'rxjs/add/operator/do';

import {
  SignInData,
  RegisterData,
  UpdatePasswordData,
  ResetPasswordData,

  UserType,
  UserData,
  AuthData,

  AuthTokenOpts,
  RequestOptions
} from './auth-token.model';

@Injectable()
export class AuthTokenService implements CanActivate, CanActivateChild {
  defaultOptions: AuthTokenOpts = {
    apiPath:                    null,
    apiBase:                    null,

    signInPath:                 'auth/sign_in',
    signInRedirect:             null,
    signInStoredUrlStorageKey:  null,

    signOutPath:                'auth/sign_out',
    validateTokenPath:          'auth/validate_token',
    signOutFailedValidate:      false,

    registerAccountPath:        'auth',
    deleteAccountPath:          'auth',
    registerAccountCallback:    window.location.href,

    updatePasswordPath:         'auth',

    resetPasswordPath:          'auth/password',
    resetPasswordCallback:      window.location.href,

    userTypes:                  null,

    oAuthBase:                  window.location.origin,
    oAuthPaths: {
      github:                   'auth/github'
    },
    oAuthCallbackPath:          'oauth_callback',
    oAuthWindowType:            'newWindow',
    oAuthWindowOptions:         null,

    globalOptions: {
      headers: {
        'Content-Type': 'application/json',
        'Accept':       'application/json'
      }
    }
  };

  get currentUserType(): string {
    if (this.atCurrentUserType != null) {
      return this.atCurrentUserType.name;
    } else {
      return null;
    }
  }

  get currentUserData(): UserData {
    return this.atCurrentUserData;
  }

  get currentAuthData(): AuthData {
    return this.atCurrentAuthData;
  }

  get currentAuthHeaders(): HttpHeaders {
    if (this.atCurrentAuthData != null) {
      return new HttpHeaders({
        'access-token': this.atCurrentAuthData.accessToken,
        'client':       this.atCurrentAuthData.client,
        'expiry':       this.atCurrentAuthData.expiry,
        'token-type':   this.atCurrentAuthData.tokenType,
        'uid':          this.atCurrentAuthData.uid
      });
    }

    return new HttpHeaders;
  }

  private atOptions: AuthTokenOpts;
  private atCurrentUserType: UserType;
  private atCurrentAuthData: AuthData;
  private atCurrentUserData: UserData;

  constructor(
    private http: HttpClient,
    @Optional() private activatedRoute: ActivatedRoute,
    @Optional() private router: Router
  ) {}

  userSignedIn(): boolean {
    return !!this.atCurrentAuthData;
  }

  canActivate(): boolean {
    if (this.userSignedIn()) {
      return true;
    } else {
      // Store current location in storage (useful for redirection after signing in)
      if (this.atOptions.signInStoredUrlStorageKey) {
        localStorage.setItem(
          this.atOptions.signInStoredUrlStorageKey,
          window.location.pathname + window.location.search
        );
      }

      // Redirect user to sign in if signInRedirect is set
      if (this.router && this.atOptions.signInRedirect) {
        this.router.navigate([this.atOptions.signInRedirect]);
      }

      return false;
    }
  }

  canActivateChild(): boolean {
    return this.canActivate();
  }

  // Inital configuration
  init(options?: AuthTokenOpts) {
    this.atOptions = (<any>Object).assign(this.defaultOptions, options);
    this.tryLoadAuthData();
  }

  /**
   *
   * Actions
   *
   */

  // Register request
  registerAccount(registerData: RegisterData): Observable<Response> {
    if (registerData.userType == null) {
      this.atCurrentUserType = null;
    } else {
      this.atCurrentUserType = this.getUserTypeByName(registerData.userType);
      delete registerData.userType;
    }

    registerData.password_confirmation  = registerData.passwordConfirmation;
    delete registerData.passwordConfirmation;

    registerData.confirm_success_url    = this.atOptions.registerAccountCallback;

    return this.post(this.getUserPath() + this.atOptions.registerAccountPath, registerData);
  }

  // Delete Account
  deleteAccount(): Observable<Response> {
    return this.delete(this.getUserPath() + this.atOptions.deleteAccountPath);
  }

  // Sign in request and set storage
  signIn(signInData: SignInData): Observable<Response> {
    if (signInData.userType == null) {
      this.atCurrentUserType = null;
    } else {
      this.atCurrentUserType = this.getUserTypeByName(signInData.userType);
    }

    const body = {
      email:      signInData.email,
      password:   signInData.password
    };

    const observ = this.post(this.getUserPath() + this.atOptions.signInPath, body);

    observ.subscribe(
      res => this.atCurrentUserData = res.body,
      err => null
    );

    return observ;
  }

  signInOAuth(oAuthType: string) {
    const oAuthPath: string = this.getOAuthPath(oAuthType);
    const callbackUrl = `${window.location.origin}/${this.atOptions.oAuthCallbackPath}`;
    const oAuthWindowType: string = this.atOptions.oAuthWindowType;
    const authUrl: string = this.getOAuthUrl(oAuthPath, callbackUrl, oAuthWindowType);

    if (oAuthWindowType === 'newWindow') {
      const oAuthWindowOptions = this.atOptions.oAuthWindowOptions;
      let windowOptions = '';

      if (oAuthWindowOptions) {
        for (const key in oAuthWindowOptions) {
          windowOptions += `,${key}=${oAuthWindowOptions[key]}`;
        }
      }

      const popup = window.open(
        authUrl,
        '_blank',
        `closebuttoncaption=Cancel${windowOptions}`
      );
      return this.requestCredentialsViaPostMessage(popup);
    } else if (oAuthWindowType === 'sameWindow') {
      window.location.href = authUrl;
    } else {
      throw `Unsupported oAuthWindowType "${oAuthWindowType}"`;
    }
  }

  processOAuthCallback(): void {
    this.getAuthDataFromParams();
  }

  // Sign out request and delete storage
  signOut(): Observable<Response> {
    const observ = this.delete(this.getUserPath() + this.atOptions.signOutPath);

    observ.subscribe(
      res => {
        localStorage.removeItem('accessToken');
        localStorage.removeItem('client');
        localStorage.removeItem('expiry');
        localStorage.removeItem('tokenType');
        localStorage.removeItem('uid');

        this.atCurrentAuthData = null;
        this.atCurrentUserType = null;
        this.atCurrentUserData = null;
      }
    );

    return observ;
  }

  // Validate token request
  validateToken(): Observable<Response> {
    const observ = this.get(this.getUserPath() + this.atOptions.validateTokenPath)

    observ.subscribe(
      res => this.atCurrentUserData = res.data,
      error => {
        if (error.status === 401 && this.atOptions.signOutFailedValidate) {
          this.signOut();
        }
      }
    );

    return observ;
  }

  // Update password request
  updatePassword(updatePasswordData: UpdatePasswordData): Observable<Response> {
    if (updatePasswordData.userType != null) {
      this.atCurrentUserType = this.getUserTypeByName(updatePasswordData.userType);
    }

    let args: any;

    if (updatePasswordData.passwordCurrent == null) {
      args = {
        password:               updatePasswordData.password,
        password_confirmation:  updatePasswordData.passwordConfirmation
      };
    } else {
      args = {
        current_password:       updatePasswordData.passwordCurrent,
        password:               updatePasswordData.password,
        password_confirmation:  updatePasswordData.passwordConfirmation
      };
    }

    if (updatePasswordData.resetPasswordToken) {
      args.reset_password_token = updatePasswordData.resetPasswordToken;
    }

    const body = args;
    return this.put(this.getUserPath() + this.atOptions.updatePasswordPath, body);
  }

  // Reset password request
  resetPassword(resetPasswordData: ResetPasswordData): Observable<Response> {

    if (resetPasswordData.userType == null) {
      this.atCurrentUserType = null;
    } else {
      this.atCurrentUserType = this.getUserTypeByName(resetPasswordData.userType);
    }

    const body = {
      email:          resetPasswordData.email,
      redirect_url:   this.atOptions.resetPasswordCallback
    };

    return this.post(this.getUserPath() + this.atOptions.resetPasswordPath, body);
  }

  /**
   *
   * HTTP Wrappers
   *
   */

  get(url: string, options?: RequestOptions): Observable<any> {
    return this.http.get(this.getApiPath() + url, options).share();
  }

  post(url: string, body: any, options?: RequestOptions): Observable<any> {
    return this.http.post(this.getApiPath() + url, body, options).share();
  }

  put(url: string, body: any, options?: RequestOptions): Observable<any> {
    return this.http.put(this.getApiPath() + url, body, options).share();
  }

  delete(url: string, options?: RequestOptions): Observable<any> {
    return this.http.delete(this.getApiPath() + url, options).share();
  }

  patch(url: string, body: any, options?: RequestOptions): Observable<any> {
    return this.http.patch(this.getApiPath() + url, body, options).share();
  }

  head(url: string, options?: RequestOptions): Observable<any> {
    return this.http.head(this.getApiPath() + url, options).share();
  }

  options(url: string, options?: RequestOptions): Observable<any> {
    return this.http.options(this.getApiPath() + url, options).share();
  }

  getCurrentAuthHeaders(): HttpHeaders {
    // Get auth data from local storage
    this.getAuthDataFromStorage();

    // Get auth data from query params to override local storage data
    if (this.activatedRoute) {
      this.getAuthDataFromParams();
    }

    let headers: any = {};

    // Merge auth headers to request if set
    if (this.atCurrentAuthData != null) {
      headers['access-token'] = this.atCurrentAuthData.accessToken;
      headers['client'] = this.atCurrentAuthData.client;
      headers['expiry'] = this.atCurrentAuthData.expiry;
      headers['token-type'] = this.atCurrentAuthData.tokenType;
      headers['uid'] = this.atCurrentAuthData.uid;
    }

    Object.keys(this.atOptions.globalOptions.headers).forEach(
      (key) => headers[key] = this.atOptions.globalOptions.headers[key]
    );

    const httpHeaders: HttpHeaders = new HttpHeaders(headers);
    return httpHeaders;
  }

  /**
   *
   * Get Auth Data
   *
   */

  // Try to load auth data
  private tryLoadAuthData(): void {

    const userType = this.getUserTypeByName(localStorage.getItem('userType'));

    if (userType) {
      this.atCurrentUserType = userType;
    }

    this.getAuthDataFromStorage();

    if (this.activatedRoute) {
      this.getAuthDataFromParams();
    }

    if (this.atCurrentAuthData) {
      this.validateToken();
    }
  }

  // Parse Auth data from response
  getAuthHeadersFromResponse(headers: HttpHeaders): void {
    const authData: AuthData = {
      accessToken:    headers.get('access-token'),
      client:         headers.get('client'),
      expiry:         headers.get('expiry'),
      tokenType:      headers.get('token-type'),
      uid:            headers.get('uid')
    };

    this.setAuthData(authData);
  }

  // Parse Auth data from post message
  private getAuthDataFromPostMessage(data: any): void {
    const authData: AuthData = {
      accessToken:    data['auth_token'],
      client:         data['client_id'],
      expiry:         data['expiry'],
      tokenType:      'Bearer',
      uid:            data['uid']
    };

    this.setAuthData(authData);
  }

  // Try to get auth data from storage.
  private getAuthDataFromStorage(): void {
    const authData: AuthData = {
      accessToken:    localStorage.getItem('accessToken'),
      client:         localStorage.getItem('client'),
      expiry:         localStorage.getItem('expiry'),
      tokenType:      localStorage.getItem('tokenType'),
      uid:            localStorage.getItem('uid')
    };

    if (this.checkAuthData(authData)) {
      this.atCurrentAuthData = authData;
    }
  }

  // Try to get auth data from url parameters.
  private getAuthDataFromParams(): void {
    if (this.activatedRoute.queryParams) { // Fix for Testing, needs to be removed later
      this.activatedRoute.queryParams.subscribe(queryParams => {
        const authData: AuthData = {
          accessToken: queryParams['token'] || queryParams['auth_token'],
          client: queryParams['client_id'],
          expiry: queryParams['expiry'],
          tokenType: 'Bearer',
          uid: queryParams['uid']
        };

        if (this.checkAuthData(authData)) {
          this.atCurrentAuthData = authData;
        }
      });
    }
  }

  /**
   *
   * Set Auth Data
   *
   */

  // Write auth data to storage
  private setAuthData(authData: AuthData): void {
    if (this.checkAuthData(authData)) {
      this.atCurrentAuthData = authData;

      localStorage.setItem('accessToken', authData.accessToken);
      localStorage.setItem('client', authData.client);
      localStorage.setItem('expiry', authData.expiry);
      localStorage.setItem('tokenType', authData.tokenType);
      localStorage.setItem('uid', authData.uid);

      if (this.atCurrentUserType != null) {
        localStorage.setItem('userType', this.atCurrentUserType.name);
      }
    }
  }

  /**
   *
   * Validate Auth Data
   *
   */

  // Check if auth data complete and if response token is newer
  private checkAuthData(authData: AuthData): boolean {
    if (
      authData.accessToken != null &&
      authData.client != null &&
      authData.expiry != null &&
      authData.tokenType != null &&
      authData.uid != null
    ) {
      if (this.atCurrentAuthData != null) {
        return authData.expiry >= this.atCurrentAuthData.expiry;
      } else {
        return true;
      }
    } else {
      return false;
    }
  }

  /**
   *
   * Construct Paths / Urls
   *
   */

  private getUserPath(): string {
    if (this.atCurrentUserType == null) {
      return '';
    } else {
      return this.atCurrentUserType.path + '/';
    }
  }

  private getApiPath(): string {
    let constructedPath = '';

    if (this.atOptions.apiBase != null) {
      constructedPath += this.atOptions.apiBase + '/';
    }

    if (this.atOptions.apiPath != null) {
      constructedPath += this.atOptions.apiPath + '/';
    }

    return constructedPath;
  }

  private getOAuthPath(oAuthType: string): string {
    let oAuthPath: string;

    oAuthPath = this.atOptions.oAuthPaths[oAuthType];

    if (oAuthPath == null) {
      oAuthPath = '/auth/${oAuthType}';
    }

    return oAuthPath;
  }

  private getOAuthUrl(oAuthPath: string, callbackUrl: string, windowType: string): string {
    let url: string;

    url =   `${this.atOptions.oAuthBase}/${oAuthPath}`;
    url +=  `?omniauth_window_type=${windowType}`;
    url +=  `&auth_origin_url=${encodeURIComponent(callbackUrl)}`;

    if (this.atCurrentUserType != null) {
      url += `&resource_class=${this.atCurrentUserType.name}`;
    }

    return url;
  }

  /**
   *
   * OAuth
   *
   */

  private requestCredentialsViaPostMessage(authWindow: any): Observable<any> {
    const pollerObserv = Observable.interval(500);

    const responseObserv = Observable.fromEvent(window, 'message').pluck('data')
      .filter(this.oAuthWindowResponseFilter);

    const responseSubscription = responseObserv.subscribe(
      this.getAuthDataFromPostMessage.bind(this)
    );

    const pollerSubscription = pollerObserv.subscribe(() => {
      if (authWindow.closed) {
        pollerSubscription.unsubscribe();
      } else {
        authWindow.postMessage('requestCredentials', '*');
      }
    });

    return responseObserv;
  }

  private oAuthWindowResponseFilter(data: any): any {
    if (data.message === 'deliverCredentials' || data.message === 'authFailure') {
      return data;
    }
  }

  /**
   *
   * Utilities
   *
   */

  // Match user config by user config name
  private getUserTypeByName(name: string): UserType {
    if (name == null || this.atOptions.userTypes == null) {
      return null;
    }

    return this.atOptions.userTypes.find(
      userType => userType.name === name
    );
  }
}
