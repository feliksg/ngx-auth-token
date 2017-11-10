import { Inject, Injectable, InjectionToken, NgModule, Optional, SkipSelf } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { HTTP_INTERCEPTORS, HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable as Observable$1 } from 'rxjs/Observable';
import 'rxjs/add/operator/share';
import 'rxjs/add/observable/interval';
import 'rxjs/add/observable/fromEvent';
import 'rxjs/add/operator/pluck';
import 'rxjs/add/operator/filter';

const AUTH_TOKEN_OPTIONS = new InjectionToken('AUTH_TOKEN_OPTIONS');

var __decorate$2 = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata$2 = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param$1 = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
let AuthTokenService = class AuthTokenService {
    constructor(http$$1, config, activatedRoute, router$$1) {
        this.http = http$$1;
        this.activatedRoute = activatedRoute;
        this.router = router$$1;
        this.defaultOptions = {
            apiPath: null,
            apiBase: null,
            signInPath: 'auth/sign_in',
            signInRedirect: null,
            signInStoredUrlStorageKey: null,
            signOutPath: 'auth/sign_out',
            validateTokenPath: 'auth/validate_token',
            signOutFailedValidate: false,
            registerAccountPath: 'auth',
            deleteAccountPath: 'auth',
            registerAccountCallback: window.location.href,
            updatePasswordPath: 'auth',
            resetPasswordPath: 'auth/password',
            resetPasswordCallback: window.location.href,
            userTypes: null,
            oAuthBase: window.location.origin,
            oAuthPaths: {
                github: 'auth/github'
            },
            oAuthCallbackPath: 'oauth_callback',
            oAuthWindowType: 'newWindow',
            oAuthWindowOptions: null,
            globalOptions: {
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
            }
        };
        if (config) {
            this.atOptions = Object.assign(this.defaultOptions, config);
        }
    }
    get currentUserType() {
        if (this.atCurrentUserType != null) {
            return this.atCurrentUserType.name;
        }
        else {
            return null;
        }
    }
    get currentUserData() {
        return this.atCurrentUserData;
    }
    get currentAuthData() {
        return this.atCurrentAuthData;
    }
    get currentAuthHeaders() {
        if (this.atCurrentAuthData != null) {
            return new HttpHeaders({
                'access-token': this.atCurrentAuthData.accessToken,
                'client': this.atCurrentAuthData.client,
                'expiry': this.atCurrentAuthData.expiry,
                'token-type': this.atCurrentAuthData.tokenType,
                'uid': this.atCurrentAuthData.uid
            });
        }
        return new HttpHeaders;
    }
    userSignedIn() {
        return !!this.atCurrentAuthData;
    }
    canActivate() {
        if (this.userSignedIn()) {
            return true;
        }
        else {
            // Store current location in storage (usefull for redirection after signing in)
            if (this.atOptions.signInStoredUrlStorageKey) {
                localStorage.setItem(this.atOptions.signInStoredUrlStorageKey, window.location.pathname + window.location.search);
            }
            // Redirect user to sign in if signInRedirect is set
            if (this.router && this.atOptions.signInRedirect) {
                this.router.navigate([this.atOptions.signInRedirect]);
            }
            return false;
        }
    }
    // Inital configuration
    init(options) {
        this.atOptions = Object.assign(this.defaultOptions, options);
        this.tryLoadAuthData();
    }
    /**
     *
     * Actions
     *
     */
    // Register request
    registerAccount(registerData) {
        if (registerData.userType == null) {
            this.atCurrentUserType = null;
        }
        else {
            this.atCurrentUserType = this.getUserTypeByName(registerData.userType);
            delete registerData.userType;
        }
        registerData.password_confirmation = registerData.passwordConfirmation;
        delete registerData.passwordConfirmation;
        registerData.confirm_success_url = this.atOptions.registerAccountCallback;
        return this.post(this.getUserPath() + this.atOptions.registerAccountPath, JSON.stringify(registerData));
    }
    // Delete Account
    deleteAccount() {
        return this.delete(this.getUserPath() + this.atOptions.deleteAccountPath);
    }
    // Sign in request and set storage
    signIn(signInData) {
        if (signInData.userType == null) {
            this.atCurrentUserType = null;
        }
        else {
            this.atCurrentUserType = this.getUserTypeByName(signInData.userType);
        }
        const body = JSON.stringify({
            email: signInData.email,
            password: signInData.password
        });
        const observ = this.post(this.getUserPath() + this.atOptions.signInPath, body);
        observ.subscribe(res => this.atCurrentUserData = res.json().data, _error => null);
        return observ;
    }
    signInOAuth(oAuthType) {
        const oAuthPath = this.getOAuthPath(oAuthType);
        const callbackUrl = '${window.location.origin}/${this.atOptions.oAuthCallbackPath}';
        const oAuthWindowType = this.atOptions.oAuthWindowType;
        const authUrl = this.getOAuthUrl(oAuthPath, callbackUrl, oAuthWindowType);
        if (oAuthWindowType === 'newWindow') {
            const oAuthWindowOptions = this.atOptions.oAuthWindowOptions;
            const popup = window.open(authUrl, '_blank', 'closebuttoncaption=Cancel${windowOptions}');
            return this.requestCredentialsViaPostMessage(popup);
        }
        else if (oAuthWindowType === 'sameWindow') {
            window.location.href = authUrl;
        }
        else {
            throw 'Unsupported oAuthWindowType "${oAuthWindowType}"';
        }
    }
    processOAuthCallback() {
        this.getAuthDataFromParams();
    }
    // Sign out request and delete storage
    signOut() {
        const observ = this.delete(this.getUserPath() + this.atOptions.signOutPath);
        localStorage.removeItem('accessToken');
        localStorage.removeItem('client');
        localStorage.removeItem('expiry');
        localStorage.removeItem('tokenType');
        localStorage.removeItem('uid');
        this.atCurrentAuthData = null;
        this.atCurrentUserType = null;
        this.atCurrentUserData = null;
        return observ;
    }
    // Validate token request
    validateToken() {
        const observ = this.get(this.getUserPath() + this.atOptions.validateTokenPath);
        observ.subscribe(res => this.atCurrentUserData = res.json().data, error => {
            if (error.status === 401 && this.atOptions.signOutFailedValidate) {
                this.signOut();
            }
        });
        return observ;
    }
    // Update password request
    updatePassword(updatePasswordData) {
        if (updatePasswordData.userType != null) {
            this.atCurrentUserType = this.getUserTypeByName(updatePasswordData.userType);
        }
        let args;
        if (updatePasswordData.passwordCurrent == null) {
            args = {
                password: updatePasswordData.password,
                password_confirmation: updatePasswordData.passwordConfirmation
            };
        }
        else {
            args = {
                current_password: updatePasswordData.passwordCurrent,
                password: updatePasswordData.password,
                password_confirmation: updatePasswordData.passwordConfirmation
            };
        }
        if (updatePasswordData.resetPasswordToken) {
            args.reset_password_token = updatePasswordData.resetPasswordToken;
        }
        const body = JSON.stringify(args);
        return this.put(this.getUserPath() + this.atOptions.updatePasswordPath, body);
    }
    // Reset password request
    resetPassword(resetPasswordData) {
        if (resetPasswordData.userType == null) {
            this.atCurrentUserType = null;
        }
        else {
            this.atCurrentUserType = this.getUserTypeByName(resetPasswordData.userType);
        }
        const body = JSON.stringify({
            email: resetPasswordData.email,
            redirect_url: this.atOptions.resetPasswordCallback
        });
        return this.post(this.getUserPath() + this.atOptions.resetPasswordPath, body);
    }
    /**
     *
     * HTTP Wrappers
     *
     */
    get(url, options) {
        const response = this.http.get(this.getApiPath() + url, options).share();
        this.handleResponse(response);
        return response;
    }
    post(url, body, options) {
        const response = this.http.post(this.getApiPath() + url, body, options).share();
        this.handleResponse(response);
        return response;
    }
    put(url, body, options) {
        const response = this.http.put(this.getApiPath() + url, body, options).share();
        this.handleResponse(response);
        return response;
    }
    delete(url, options) {
        const response = this.http.delete(this.getApiPath() + url, options).share();
        this.handleResponse(response);
        return response;
    }
    patch(url, body, options) {
        const response = this.http.patch(this.getApiPath() + url, body, options).share();
        this.handleResponse(response);
        return response;
    }
    head(url, options) {
        const response = this.http.head(this.getApiPath() + url, options).share();
        this.handleResponse(response);
        return response;
    }
    options(url, options) {
        const response = this.http.options(this.getApiPath() + url, options).share();
        this.handleResponse(response);
        return response;
    }
    setCurrentAuthHeaders() {
        // Get auth data from local storage
        this.getAuthDataFromStorage();
        // Get auth data from query params to override local storage data
        this.getAuthDataFromParams();
        const headers = new HttpHeaders();
        // Merge auth headers to request if set
        if (this.atCurrentAuthData != null) {
            headers.append('access-token', this.atCurrentAuthData.accessToken);
            headers.append('client', this.atCurrentAuthData.client);
            headers.append('expiry', this.atCurrentAuthData.expiry);
            headers.append('token-type', this.atCurrentAuthData.tokenType);
            headers.append('uid', this.atCurrentAuthData.uid);
        }
        Object.keys(this.atOptions.globalOptions.headers).forEach((key) => headers.append(key, this.atOptions.globalOptions.headers[key]));
        return headers;
    }
    // // Construct and send Http request
    // request(options: RequestOptionsArgs): Observable<Response> {
    //
    //     let baseRequestOptions: RequestOptions;
    //     let baseHeaders:        { [key:string]: string; } = this.atOptions.globalOptions.headers;
    //
    //     // Get auth data from local storage
    //     this.getAuthDataFromStorage();
    //
    //     // Merge auth headers to request if set
    //     if (this.atCurrentAuthData != null) {
    //         (<any>Object).assign(baseHeaders, {
    //             'access-token': this.atCurrentAuthData.accessToken,
    //             'client':       this.atCurrentAuthData.client,
    //             'expiry':       this.atCurrentAuthData.expiry,
    //             'token-type':   this.atCurrentAuthData.tokenType,
    //             'uid':          this.atCurrentAuthData.uid
    //         });
    //     }
    //
    //     baseRequestOptions = new RequestOptions({
    //         headers: new Headers(baseHeaders)
    //     });
    //
    //     // Merge standard and custom RequestOptions
    //     baseRequestOptions = baseRequestOptions.merge(options);
    //
    //     let response = this.http.request(new Request(baseRequestOptions)).share();
    //     this.handleResponse(response);
    //
    //     return response;
    // }
    //
    // private mergeRequestOptionsArgs(options: RequestOptionsArgs, addOptions?: RequestOptionsArgs): RequestOptionsArgs {
    //
    //     let returnOptions: RequestOptionsArgs = options;
    //
    //     if (options)
    //         (<any>Object).assign(returnOptions, addOptions);
    //
    //     return returnOptions;
    // }
    // Check if response is complete and newer, then update storage
    handleResponse(request) {
        request.subscribe(res => {
            this.getAuthHeadersFromResponse(res);
        }, error => {
            this.getAuthHeadersFromResponse(error);
        });
    }
    /**
     *
     * Get Auth Data
     *
     */
    // Try to load auth data
    tryLoadAuthData() {
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
    getAuthHeadersFromResponse(data) {
        const headers = data.headers;
        const authData = {
            accessToken: headers.get('access-token'),
            client: headers.get('client'),
            expiry: headers.get('expiry'),
            tokenType: headers.get('token-type'),
            uid: headers.get('uid')
        };
        this.setAuthData(authData);
    }
    // Parse Auth data from post message
    getAuthDataFromPostMessage(data) {
        const authData = {
            accessToken: data['auth_token'],
            client: data['client_id'],
            expiry: data['expiry'],
            tokenType: 'Bearer',
            uid: data['uid']
        };
        this.setAuthData(authData);
    }
    // Try to get auth data from storage.
    getAuthDataFromStorage() {
        const authData = {
            accessToken: localStorage.getItem('accessToken'),
            client: localStorage.getItem('client'),
            expiry: localStorage.getItem('expiry'),
            tokenType: localStorage.getItem('tokenType'),
            uid: localStorage.getItem('uid')
        };
        if (this.checkAuthData(authData)) {
            this.atCurrentAuthData = authData;
        }
    }
    // Try to get auth data from url parameters.
    getAuthDataFromParams() {
        if (this.activatedRoute.queryParams) {
            this.activatedRoute.queryParams.subscribe(queryParams => {
                const authData = {
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
    setAuthData(authData) {
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
    checkAuthData(authData) {
        if (authData.accessToken != null &&
            authData.client != null &&
            authData.expiry != null &&
            authData.tokenType != null &&
            authData.uid != null) {
            if (this.atCurrentAuthData != null) {
                return authData.expiry >= this.atCurrentAuthData.expiry;
            }
            else {
                return true;
            }
        }
        else {
            return false;
        }
    }
    /**
     *
     * Construct Paths / Urls
     *
     */
    getUserPath() {
        if (this.atCurrentUserType == null) {
            return '';
        }
        else {
            return this.atCurrentUserType.path + '/';
        }
    }
    getApiPath() {
        let constructedPath = '';
        if (this.atOptions.apiBase != null) {
            constructedPath += this.atOptions.apiBase + '/';
        }
        if (this.atOptions.apiPath != null) {
            constructedPath += this.atOptions.apiPath + '/';
        }
        return constructedPath;
    }
    getOAuthPath(oAuthType) {
        let oAuthPath;
        oAuthPath = this.atOptions.oAuthPaths[oAuthType];
        if (oAuthPath == null) {
            oAuthPath = '/auth/${oAuthType}';
        }
        return oAuthPath;
    }
    getOAuthUrl(oAuthPath, callbackUrl, windowType) {
        let url;
        url = '${this.atOptions.oAuthBase}/${oAuthPath}';
        url += '?omniauth_window_type=${windowType}';
        url += '&auth_origin_url=${encodeURIComponent(callbackUrl)}';
        if (this.atCurrentUserType != null) {
            url += '&resource_class=${this.atCurrentUserType.name}';
        }
        return url;
    }
    /**
     *
     * OAuth
     *
     */
    requestCredentialsViaPostMessage(authWindow) {
        const pollerObserv = Observable$1.interval(500);
        const responseObserv = Observable$1.fromEvent(window, 'message').pluck('data')
            .filter(this.oAuthWindowResponseFilter);
        const responseSubscription = responseObserv.subscribe(this.getAuthDataFromPostMessage.bind(this));
        const pollerSubscription = pollerObserv.subscribe(() => {
            if (authWindow.closed) {
                pollerSubscription.unsubscribe();
            }
            else {
                authWindow.postMessage('requestCredentials', '*');
            }
        });
        return responseObserv;
    }
    oAuthWindowResponseFilter(data) {
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
    getUserTypeByName(name) {
        if (name == null || this.atOptions.userTypes == null) {
            return null;
        }
        return this.atOptions.userTypes.find(userType => userType.name === name);
    }
};
AuthTokenService = __decorate$2([
    Injectable(),
    __param$1(0, Inject(HttpClient)),
    __param$1(1, Inject(AUTH_TOKEN_OPTIONS)),
    __param$1(2, Optional()), __param$1(2, Inject(ActivatedRoute)),
    __param$1(3, Optional()), __param$1(3, Inject(Router)),
    __metadata$2("design:paramtypes", [HttpClient, Object, ActivatedRoute,
        Router])
], AuthTokenService);

var __decorate$1 = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata$1 = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
let AuthTokenInterceptor = class AuthTokenInterceptor {
    constructor(authTokenService) {
        this.authTokenService = authTokenService;
    }
    intercept(req, next) {
        this.authTokenService.setCurrentAuthHeaders();
        const authHeaders = this.authTokenService.currentAuthHeaders;
        authHeaders.keys().forEach((key) => req.headers.append(key, authHeaders.get(key)));
        const authReq = req.clone({ headers: req.headers });
        return next.handle(authReq);
    }
};
AuthTokenInterceptor = __decorate$1([
    Injectable(),
    __metadata$1("design:paramtypes", [AuthTokenService])
], AuthTokenInterceptor);

var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
let AuthTokenModule = AuthTokenModule_1 = class AuthTokenModule {
    constructor(parentModule) {
        if (parentModule) {
            throw new Error('AuthTokenModule is already loaded. It should only be imported in your application\'s main module.');
        }
    }
    static forRoot(options) {
        return {
            ngModule: AuthTokenModule_1,
            providers: [
                {
                    provide: HTTP_INTERCEPTORS,
                    useClass: AuthTokenInterceptor,
                    multi: true
                },
                options.authTokenOptionsProvider ||
                    {
                        provide: AUTH_TOKEN_OPTIONS,
                        useValue: options.config
                    },
                AuthTokenService
            ]
        };
    }
};
AuthTokenModule = AuthTokenModule_1 = __decorate([
    NgModule(),
    __param(0, Optional()), __param(0, SkipSelf()),
    __metadata("design:paramtypes", [AuthTokenModule])
], AuthTokenModule);
var AuthTokenModule_1;

/**
 * Generated bundle index. Do not edit.
 */

export { AuthTokenModule, AuthTokenInterceptor, AuthTokenService, AUTH_TOKEN_OPTIONS };
//# sourceMappingURL=ngx-token-auth.js.map
