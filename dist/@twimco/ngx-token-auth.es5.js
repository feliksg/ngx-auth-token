import { Inject, Injectable, InjectionToken, NgModule, Optional, SkipSelf } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { HTTP_INTERCEPTORS, HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable as Observable$1 } from 'rxjs/Observable';
import 'rxjs/add/operator/share';
import 'rxjs/add/observable/interval';
import 'rxjs/add/observable/fromEvent';
import 'rxjs/add/operator/pluck';
import 'rxjs/add/operator/filter';
var AUTH_TOKEN_OPTIONS = new InjectionToken('AUTH_TOKEN_OPTIONS');
var __decorate$2 = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function")
        r = Reflect.decorate(decorators, target, key, desc);
    else
        for (var i = decorators.length - 1; i >= 0; i--)
            if (d = decorators[i])
                r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata$2 = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function")
        return Reflect.metadata(k, v);
};
var __param$1 = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); };
};
var AuthTokenService = (function () {
    function AuthTokenService(http$$1, config, activatedRoute, router$$1) {
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
    Object.defineProperty(AuthTokenService.prototype, "currentUserType", {
        get: function () {
            if (this.atCurrentUserType != null) {
                return this.atCurrentUserType.name;
            }
            else {
                return null;
            }
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(AuthTokenService.prototype, "currentUserData", {
        get: function () {
            return this.atCurrentUserData;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(AuthTokenService.prototype, "currentAuthData", {
        get: function () {
            return this.atCurrentAuthData;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(AuthTokenService.prototype, "currentAuthHeaders", {
        get: function () {
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
        },
        enumerable: true,
        configurable: true
    });
    AuthTokenService.prototype.userSignedIn = function () {
        return !!this.atCurrentAuthData;
    };
    AuthTokenService.prototype.canActivate = function () {
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
    };
    // Inital configuration
    AuthTokenService.prototype.init = function (options) {
        this.atOptions = Object.assign(this.defaultOptions, options);
        this.tryLoadAuthData();
    };
    /**
     *
     * Actions
     *
     */
    // Register request
    AuthTokenService.prototype.registerAccount = function (registerData) {
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
    };
    // Delete Account
    AuthTokenService.prototype.deleteAccount = function () {
        return this.delete(this.getUserPath() + this.atOptions.deleteAccountPath);
    };
    // Sign in request and set storage
    AuthTokenService.prototype.signIn = function (signInData) {
        var _this = this;
        if (signInData.userType == null) {
            this.atCurrentUserType = null;
        }
        else {
            this.atCurrentUserType = this.getUserTypeByName(signInData.userType);
        }
        var body = JSON.stringify({
            email: signInData.email,
            password: signInData.password
        });
        var observ = this.post(this.getUserPath() + this.atOptions.signInPath, body);
        observ.subscribe(function (res) { return _this.atCurrentUserData = res.json().data; }, function (_error) { return null; });
        return observ;
    };
    AuthTokenService.prototype.signInOAuth = function (oAuthType) {
        var oAuthPath = this.getOAuthPath(oAuthType);
        var callbackUrl = '${window.location.origin}/${this.atOptions.oAuthCallbackPath}';
        var oAuthWindowType = this.atOptions.oAuthWindowType;
        var authUrl = this.getOAuthUrl(oAuthPath, callbackUrl, oAuthWindowType);
        if (oAuthWindowType === 'newWindow') {
            var oAuthWindowOptions = this.atOptions.oAuthWindowOptions;
            var popup = window.open(authUrl, '_blank', 'closebuttoncaption=Cancel${windowOptions}');
            return this.requestCredentialsViaPostMessage(popup);
        }
        else if (oAuthWindowType === 'sameWindow') {
            window.location.href = authUrl;
        }
        else {
            throw 'Unsupported oAuthWindowType "${oAuthWindowType}"';
        }
    };
    AuthTokenService.prototype.processOAuthCallback = function () {
        this.getAuthDataFromParams();
    };
    // Sign out request and delete storage
    AuthTokenService.prototype.signOut = function () {
        var observ = this.delete(this.getUserPath() + this.atOptions.signOutPath);
        localStorage.removeItem('accessToken');
        localStorage.removeItem('client');
        localStorage.removeItem('expiry');
        localStorage.removeItem('tokenType');
        localStorage.removeItem('uid');
        this.atCurrentAuthData = null;
        this.atCurrentUserType = null;
        this.atCurrentUserData = null;
        return observ;
    };
    // Validate token request
    AuthTokenService.prototype.validateToken = function () {
        var _this = this;
        var observ = this.get(this.getUserPath() + this.atOptions.validateTokenPath);
        observ.subscribe(function (res) { return _this.atCurrentUserData = res.json().data; }, function (error) {
            if (error.status === 401 && _this.atOptions.signOutFailedValidate) {
                _this.signOut();
            }
        });
        return observ;
    };
    // Update password request
    AuthTokenService.prototype.updatePassword = function (updatePasswordData) {
        if (updatePasswordData.userType != null) {
            this.atCurrentUserType = this.getUserTypeByName(updatePasswordData.userType);
        }
        var args;
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
        var body = JSON.stringify(args);
        return this.put(this.getUserPath() + this.atOptions.updatePasswordPath, body);
    };
    // Reset password request
    AuthTokenService.prototype.resetPassword = function (resetPasswordData) {
        if (resetPasswordData.userType == null) {
            this.atCurrentUserType = null;
        }
        else {
            this.atCurrentUserType = this.getUserTypeByName(resetPasswordData.userType);
        }
        var body = JSON.stringify({
            email: resetPasswordData.email,
            redirect_url: this.atOptions.resetPasswordCallback
        });
        return this.post(this.getUserPath() + this.atOptions.resetPasswordPath, body);
    };
    /**
     *
     * HTTP Wrappers
     *
     */
    AuthTokenService.prototype.get = function (url, options) {
        var response = this.http.get(this.getApiPath() + url, options).share();
        this.handleResponse(response);
        return response;
    };
    AuthTokenService.prototype.post = function (url, body, options) {
        var response = this.http.post(this.getApiPath() + url, body, options).share();
        this.handleResponse(response);
        return response;
    };
    AuthTokenService.prototype.put = function (url, body, options) {
        var response = this.http.put(this.getApiPath() + url, body, options).share();
        this.handleResponse(response);
        return response;
    };
    AuthTokenService.prototype.delete = function (url, options) {
        var response = this.http.delete(this.getApiPath() + url, options).share();
        this.handleResponse(response);
        return response;
    };
    AuthTokenService.prototype.patch = function (url, body, options) {
        var response = this.http.patch(this.getApiPath() + url, body, options).share();
        this.handleResponse(response);
        return response;
    };
    AuthTokenService.prototype.head = function (url, options) {
        var response = this.http.head(this.getApiPath() + url, options).share();
        this.handleResponse(response);
        return response;
    };
    AuthTokenService.prototype.options = function (url, options) {
        var response = this.http.options(this.getApiPath() + url, options).share();
        this.handleResponse(response);
        return response;
    };
    AuthTokenService.prototype.setCurrentAuthHeaders = function () {
        var _this = this;
        // Get auth data from local storage
        this.getAuthDataFromStorage();
        // Get auth data from query params to override local storage data
        this.getAuthDataFromParams();
        var headers = new HttpHeaders();
        // Merge auth headers to request if set
        if (this.atCurrentAuthData != null) {
            headers.append('access-token', this.atCurrentAuthData.accessToken);
            headers.append('client', this.atCurrentAuthData.client);
            headers.append('expiry', this.atCurrentAuthData.expiry);
            headers.append('token-type', this.atCurrentAuthData.tokenType);
            headers.append('uid', this.atCurrentAuthData.uid);
        }
        Object.keys(this.atOptions.globalOptions.headers).forEach(function (key) { return headers.append(key, _this.atOptions.globalOptions.headers[key]); });
        return headers;
    };
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
    AuthTokenService.prototype.handleResponse = function (request) {
        var _this = this;
        request.subscribe(function (res) {
            _this.getAuthHeadersFromResponse(res);
        }, function (error) {
            _this.getAuthHeadersFromResponse(error);
        });
    };
    /**
     *
     * Get Auth Data
     *
     */
    // Try to load auth data
    AuthTokenService.prototype.tryLoadAuthData = function () {
        var userType = this.getUserTypeByName(localStorage.getItem('userType'));
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
    };
    // Parse Auth data from response
    AuthTokenService.prototype.getAuthHeadersFromResponse = function (data) {
        var headers = data.headers;
        var authData = {
            accessToken: headers.get('access-token'),
            client: headers.get('client'),
            expiry: headers.get('expiry'),
            tokenType: headers.get('token-type'),
            uid: headers.get('uid')
        };
        this.setAuthData(authData);
    };
    // Parse Auth data from post message
    AuthTokenService.prototype.getAuthDataFromPostMessage = function (data) {
        var authData = {
            accessToken: data['auth_token'],
            client: data['client_id'],
            expiry: data['expiry'],
            tokenType: 'Bearer',
            uid: data['uid']
        };
        this.setAuthData(authData);
    };
    // Try to get auth data from storage.
    AuthTokenService.prototype.getAuthDataFromStorage = function () {
        var authData = {
            accessToken: localStorage.getItem('accessToken'),
            client: localStorage.getItem('client'),
            expiry: localStorage.getItem('expiry'),
            tokenType: localStorage.getItem('tokenType'),
            uid: localStorage.getItem('uid')
        };
        if (this.checkAuthData(authData)) {
            this.atCurrentAuthData = authData;
        }
    };
    // Try to get auth data from url parameters.
    AuthTokenService.prototype.getAuthDataFromParams = function () {
        var _this = this;
        if (this.activatedRoute.queryParams) {
            this.activatedRoute.queryParams.subscribe(function (queryParams) {
                var authData = {
                    accessToken: queryParams['token'] || queryParams['auth_token'],
                    client: queryParams['client_id'],
                    expiry: queryParams['expiry'],
                    tokenType: 'Bearer',
                    uid: queryParams['uid']
                };
                if (_this.checkAuthData(authData)) {
                    _this.atCurrentAuthData = authData;
                }
            });
        }
    };
    /**
     *
     * Set Auth Data
     *
     */
    // Write auth data to storage
    AuthTokenService.prototype.setAuthData = function (authData) {
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
    };
    /**
     *
     * Validate Auth Data
     *
     */
    // Check if auth data complete and if response token is newer
    AuthTokenService.prototype.checkAuthData = function (authData) {
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
    };
    /**
     *
     * Construct Paths / Urls
     *
     */
    AuthTokenService.prototype.getUserPath = function () {
        if (this.atCurrentUserType == null) {
            return '';
        }
        else {
            return this.atCurrentUserType.path + '/';
        }
    };
    AuthTokenService.prototype.getApiPath = function () {
        var constructedPath = '';
        if (this.atOptions.apiBase != null) {
            constructedPath += this.atOptions.apiBase + '/';
        }
        if (this.atOptions.apiPath != null) {
            constructedPath += this.atOptions.apiPath + '/';
        }
        return constructedPath;
    };
    AuthTokenService.prototype.getOAuthPath = function (oAuthType) {
        var oAuthPath;
        oAuthPath = this.atOptions.oAuthPaths[oAuthType];
        if (oAuthPath == null) {
            oAuthPath = '/auth/${oAuthType}';
        }
        return oAuthPath;
    };
    AuthTokenService.prototype.getOAuthUrl = function (oAuthPath, callbackUrl, windowType) {
        var url;
        url = '${this.atOptions.oAuthBase}/${oAuthPath}';
        url += '?omniauth_window_type=${windowType}';
        url += '&auth_origin_url=${encodeURIComponent(callbackUrl)}';
        if (this.atCurrentUserType != null) {
            url += '&resource_class=${this.atCurrentUserType.name}';
        }
        return url;
    };
    /**
     *
     * OAuth
     *
     */
    AuthTokenService.prototype.requestCredentialsViaPostMessage = function (authWindow) {
        var pollerObserv = Observable$1.interval(500);
        var responseObserv = Observable$1.fromEvent(window, 'message').pluck('data')
            .filter(this.oAuthWindowResponseFilter);
        var responseSubscription = responseObserv.subscribe(this.getAuthDataFromPostMessage.bind(this));
        var pollerSubscription = pollerObserv.subscribe(function () {
            if (authWindow.closed) {
                pollerSubscription.unsubscribe();
            }
            else {
                authWindow.postMessage('requestCredentials', '*');
            }
        });
        return responseObserv;
    };
    AuthTokenService.prototype.oAuthWindowResponseFilter = function (data) {
        if (data.message === 'deliverCredentials' || data.message === 'authFailure') {
            return data;
        }
    };
    /**
     *
     * Utilities
     *
     */
    // Match user config by user config name
    AuthTokenService.prototype.getUserTypeByName = function (name) {
        if (name == null || this.atOptions.userTypes == null) {
            return null;
        }
        return this.atOptions.userTypes.find(function (userType) { return userType.name === name; });
    };
    return AuthTokenService;
}());
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
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function")
        r = Reflect.decorate(decorators, target, key, desc);
    else
        for (var i = decorators.length - 1; i >= 0; i--)
            if (d = decorators[i])
                r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata$1 = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function")
        return Reflect.metadata(k, v);
};
var AuthTokenInterceptor = (function () {
    function AuthTokenInterceptor(authTokenService) {
        this.authTokenService = authTokenService;
    }
    AuthTokenInterceptor.prototype.intercept = function (req, next) {
        this.authTokenService.setCurrentAuthHeaders();
        var authHeaders = this.authTokenService.currentAuthHeaders;
        authHeaders.keys().forEach(function (key) { return req.headers.append(key, authHeaders.get(key)); });
        var authReq = req.clone({ headers: req.headers });
        return next.handle(authReq);
    };
    return AuthTokenInterceptor;
}());
AuthTokenInterceptor = __decorate$1([
    Injectable(),
    __metadata$1("design:paramtypes", [AuthTokenService])
], AuthTokenInterceptor);
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function")
        r = Reflect.decorate(decorators, target, key, desc);
    else
        for (var i = decorators.length - 1; i >= 0; i--)
            if (d = decorators[i])
                r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function")
        return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); };
};
var AuthTokenModule = AuthTokenModule_1 = (function () {
    function AuthTokenModule(parentModule) {
        if (parentModule) {
            throw new Error('AuthTokenModule is already loaded. It should only be imported in your application\'s main module.');
        }
    }
    AuthTokenModule.forRoot = function (options) {
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
    };
    return AuthTokenModule;
}());
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
//# sourceMappingURL=ngx-token-auth.es5.js.map
