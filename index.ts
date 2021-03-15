const oauthSignature = require('oauth-signature');
import fetch from 'node-fetch';

const LocalStorage = require('node-localstorage').LocalStorage
const local_storage = new LocalStorage('localStorage')


const delay = (ms: number) => {
    return new Promise(resolve => setTimeout(resolve, ms))
}

export interface ETradeConfig {
    watchList: string
    useKeys: string
    accountIdKey: string
}

export interface KeyConfig {
   isProduction: boolean
   key: string
   secret: string
}

export interface KeySet {
    sandbox: KeyConfig
    production: KeyConfig
}

export interface OAuthToken {
    oauth_token: string
    oauth_token_secret: string
}

export interface AccountListResponse {
    Accounts: {
        Account: {
            accountId: string
            accountIdKey: string
            accountMode: string
            accountDesc: string
            accountName: string
            accountType: string
            institutionType: string
            accountStatus: string
            closedDate: number
        }[]
    }
}

export interface QuoteResponse {
    QuoteData: {
        dateTime: string
        dateTimeUTC: number
        quoteStatus: string
        ahFlag: string
        hasMiniOptions: boolean
        All: {
            adjustedFlag: boolean
            ask: number
            askSize: number
            askTime: string
            bid: number
            bidExchange: string
            bidSize: number
            bidTime: string
            changeClose: number
            changeClosePercentage: number
            companyName: string
            daysToExpiration: number
            dirLast: string
            dividend: number
            eps: number
            estEarnings: number
            exDividendDate: number
            high: number
            high52: number
            lastTrade: number
            low: number
            low52: number
            open: number
            openInterest: number
            optionStyle: string
            optionUnderlier: string
            previousClose: number
            previousDayVolume: number
            primaryExchange: string
            symbolDescription: string
            totalVolume: number
            upc: number
            cashDeliverable: number
            marketCap: number
            sharesOutstanding: number
            nextEarningDate: string
            beta: number
            yield: number
            declaredDividend: number
            dividendPayableDate: number
            pe: number
            week52LowDate: number
            week52HiDate: number
            intrinsicValue: number
            timePremium: number
            optionMultiplier: number
            contractSize: number
            expirationDate: number
            timeOfLastTrade: number
            averageVolume: number
            ExtendedHourQuoteDetail: {
                lastPrice: number
                change: number
                percentChange: number
                bid: number
                bidSize: number
                ask: number
                askSize: number
                volume: number
                timeOfLastTrade: number
                timeZone: string
                quoteStatus: string
            }
        }
        Product: {
            symbol: string
            securityType: string
            securitySubType?: string
        }
    }[]
}

export interface BalanceResponse {
    accountId: string
    accountType: string
    optionLevel: string
    accountDescription: string
    quoteMode: number
    dayTraderStatus: string
    accountMode: string
    Cash: {
        fundsForOpenOrdersCash: number
        moneyMktBalance: number
    }
    Computed: {
        cashAvailableForInvestment: number
        cashAvailableForWithdrawal: number
        totalAvailableForWithdrawal: number
        netCash: number
        cashBalance: number
        settledCashForInvestment: number
        unSettledCashForInvestment: number
        fundsWithheldFromPurchasePower: number
        fundsWithheldFromWithdrawal: number
        marginBuyingPower: number
        cashBuyingPower: number
        dtMarginBuyingPower: number
        dtCashBuyingPower: number
        marginBalance: number
        shortAdjustBalance: number
        regtEquity: number
        regtEquityPercent: number
        accountBalance: number
        OpenCalls: {
            minEquityCall: number
            fedCall: number
            cashCall: number
            houseCall: number
        }
        RealTimeValues: {
            totalAccountValue: number
            netMv: number
            netMvLong: number
            netMvShort: number
        }
    }
    Margin: {
        dtCashOpenOrderReserve: number
        dtMarginOpenOrderReserve: number
    }
}

function randomString (length:number) {
    let text = '';
    const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    for(var i = 0; i < length; i++) {
        text += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    return text;
}

function oauthTemplate(keys:KeyConfig) {
    return {
		oauth_consumer_key : keys.key,
		oauth_nonce : randomString(16),
		oauth_timestamp : Math.floor(Date.now() / 1000).toString(),
        oauth_signature_method : 'HMAC-SHA1',
	};
}

function stringify(params:any, no_encode:boolean = false) {
    let result = '';
    for (const [key,value] of Object.entries(params)) {
        result += key + '=' + (no_encode ? value+'&' : '"'+encodeURIComponent(value as string|number|boolean)+'",');
    }
    return result.slice(0, -1);
}

function parseURLParams(response:string):any {
    const responseParams = new URLSearchParams(response);
    let result:any = {};
    for (const [key,value] of responseParams.entries()) {
        result[key] = value;
    }
    return result;
}

function signParams(
    httpMethod:string,
    url:string,
    headerParams:any,
    consumerSecret:string,
    tokenSecret:string = "",
    queryParams:any = {}) {

    const mergedParams = Object.assign({}, headerParams, queryParams);
    const encodedSignature = oauthSignature.generate(httpMethod, url, mergedParams, consumerSecret, tokenSecret, {encodeSignature: false});
    return Object.assign({ oauth_signature: encodedSignature, }, headerParams);
}

function attachQueryToUrl(url:string, query:string) {
    return (query) ? url+'?'+stringify(query, true) : url;
}

async function run(
    httpMethod:string,
    url:string,
    query:any,
    accessToken:OAuthToken,
    keys:KeyConfig,
    data:any = {}) {

    console.log(httpMethod, url, query);
    const params = Object.assign({ oauth_token: accessToken.oauth_token }, oauthTemplate(keys));
    const signedParams = signParams(httpMethod, url, params, keys.secret, accessToken.oauth_token_secret, query);
    const authString = 'OAuth realm="",' + stringify(signedParams);

    let body = "", headers:any = {Authorization: authString};
    if (httpMethod === 'POST' || httpMethod === 'PUT') {
        body = JSON.stringify(data);
        headers['Content-Type'] = 'application/json';
    }

    const fetchParams = {headers: headers, method: httpMethod, body: body.length ? body : undefined};
    const response = await fetch(attachQueryToUrl(url, query), fetchParams);

    if (response.status === 200) {
        return await response.json();
    } else if (response.status === 204) {
        return {};
    } else {
        throw (await response.json()).Error;
    }
}

function buildUrl(isProd:boolean, api:string):string {
    const host = isProd ? 'api' : 'apisb';
    return `https://${host}.etrade.com/v1/${api}.json`;
}

export async function getRequestToken(keys:KeyConfig):Promise<OAuthToken> {
    const httpMethod = 'GET';
    const url = 'https://api.etrade.com/oauth/request_token';

    const params = Object.assign({ oauth_callback: 'oob' }, oauthTemplate(keys));
    const signedParams = signParams(httpMethod, url, params, keys.secret);
    const authString = 'OAuth realm="",' + stringify(signedParams);
    const response = await (await fetch(url, {headers: {Authorization: authString}, method: httpMethod})).text();
    return parseURLParams(response);
}

export function getAuthorizeUrl(keys:KeyConfig, requestToken:OAuthToken):string {
    const url = 'https://us.etrade.com/e/t/etws/authorize';
    debugger;
    return `${url}?key=${keys.key}&token=${requestToken.oauth_token}`;
}

export async function getAccessToken(keys:KeyConfig, requestToken:OAuthToken, verifier:string) {
    const httpMethod = 'GET';
    const url = 'https://api.etrade.com/oauth/access_token';
    debugger;
    const params = Object.assign({ oauth_token: requestToken.oauth_token, oauth_verifier: verifier }, oauthTemplate(keys));
    const signedParams = signParams(httpMethod, url, params, keys.secret, requestToken.oauth_token_secret);
    const authString = 'OAuth realm="",' + stringify(signedParams);
    const response = await (await fetch(url, {headers: {Authorization: authString}, method: httpMethod})).text();
    return parseURLParams(response);
}

// ACCOUNT

export async function getAccountList(keys:KeyConfig, accessToken:OAuthToken):Promise<AccountListResponse> {
    const url = buildUrl(keys.isProduction, `accounts/list`)
    return (await run('GET', url, "", accessToken, keys)).AccountListResponse
}

export async function getBalance(accountIdKey:string, query:any, keys:KeyConfig, accessToken:OAuthToken):Promise<BalanceResponse> {
    const url = buildUrl(keys.isProduction, `accounts/${accountIdKey}/balance`)
    return (await run('GET', url, query, accessToken, keys)).BalanceResponse
}

export function getPortfolio(accountIdKey:string, query:any, keys:KeyConfig, accessToken:OAuthToken):Promise<any> {
    const url = buildUrl(keys.isProduction, `accounts/${accountIdKey}/portfolio`);
    return run('GET', url, query, accessToken, keys);
}

export function getTransactions(accountIdKey:string, query:any, keys:KeyConfig, accessToken:OAuthToken):Promise<any> {
    const url = buildUrl(keys.isProduction, `accounts/${accountIdKey}/transactions`);
    return run('GET', url, query, accessToken, keys);
}

// ORDERS

export function getOrders(accountIdKey:string, query:any, keys:KeyConfig, accessToken:OAuthToken):Promise<any> {
    const url = buildUrl(keys.isProduction, `accounts/${accountIdKey}/orders`);
    return run('GET', url, query, accessToken, keys);
}

export function previewOrder(accountIdKey:string, data:any, keys:KeyConfig, accessToken:OAuthToken):Promise<any> {
    const url = buildUrl(keys.isProduction, `accounts/${accountIdKey}/orders/preview`);
    return run('POST', url, null, accessToken, keys, {PreviewOrderRequest: data});
}

export function placeOrder(accountIdKey:string, data:any, keys:KeyConfig, accessToken:OAuthToken):Promise<any> {
    const url = buildUrl(keys.isProduction, `accounts/${accountIdKey}/orders/place`);
    return run('POST', url, null, accessToken, keys, {PlaceOrderRequest: data});
}

export function cancelOrder(accountIdKey:string, data:any, keys:KeyConfig, accessToken:OAuthToken):Promise<any> {
    const url = buildUrl(keys.isProduction, `accounts/${accountIdKey}/orders/cancel`);
    return run('PUT', url, null, accessToken, keys, {CancelOrderRequest: data});
}

// MARKET

export async function getQuotes(symbols:string, query:any, keys:KeyConfig, accessToken:OAuthToken):Promise<QuoteResponse> {
    const url = buildUrl(keys.isProduction, `market/quote/${symbols}`)
    return (await run('GET', url, query, accessToken, keys)).QuoteResponse
}

export interface Tick {
    balance: number
    quotes: QuoteResponse
}

export class Order {
    timestamp:number
    symbol:string
    shares:number
    limit:number
    toOpen:boolean
    isOrderFilled:boolean

    constructor( timestamp:number, symbol:string, shares:number, limit:number, toOpen:boolean ) {
        this.timestamp = timestamp
        this.symbol = symbol
        this.shares = shares
        this.limit = limit
        this.toOpen = toOpen
        this.isOrderFilled = false
    }
}

export class Position {
    costBasis: number //avg cost per share
    marker: number //last share price
    symbol: string
    shares: number

    constructor(
        costBasis: number,
        marker: number,
        symbol: string,
        shares: number
    ) {
        this.costBasis = costBasis
        this.marker = marker
        this.symbol = symbol
        this.shares = shares
    }
}

export interface Broker extends AsyncIterator<Tick>{
    connect:() => Promise<void>
    [Symbol.asyncIterator]:() => Broker
    next:() => Promise<IteratorResult<Tick>>
    createOrder:(symbol:string, shares:number, limit:number, toOpen:boolean) => Promise<void>
    getOrders:() => Promise<Order[]>
    getPositions:() => Promise<Position[]>
}

export class ETradeBroker implements Broker {

    accountIdKey:string
    watchList:string
    keyConfig:KeyConfig
    accessToken:OAuthToken
    hadOpenHours:boolean
    sleepDuration:number

    constructor(config:ETradeConfig, keys:KeySet, sleepDuration:number) {
        this.keyConfig = (config.useKeys === "production") ? keys.production : keys.sandbox
        this.accountIdKey = config.accountIdKey
        this.watchList = config.watchList
        this.accessToken = {} as OAuthToken
        this.hadOpenHours = false
        this.sleepDuration = sleepDuration
    }

    async connect() {

        let accountList: AccountListResponse | null = null

        if (process.argv.length > 2) {
            await this.submitCode()
        } else {
            this.accessToken = JSON.parse(local_storage.getItem('accessToken'))
            try {
                accountList = await getAccountList(this.keyConfig, this.accessToken)
            } catch (error) {
                const requestToken = await getRequestToken(this.keyConfig)
                local_storage.setItem("requestToken", JSON.stringify(requestToken))
                const authorizeUrl = getAuthorizeUrl(this.keyConfig, requestToken)
                console.log(authorizeUrl)
                process.exit(0)
            }
        }
        console.log((accountList || (await getAccountList(this.keyConfig, this.accessToken))).Accounts)
    }

    [Symbol.asyncIterator]() {return this}

    getOrders(): Promise<Order[]> {return Promise.resolve([])}
    getPositions(): Promise<Position[]> {return Promise.resolve([])}

    async submitCode(): Promise<any> {
        const code = process.argv[2]
        const requestToken = JSON.parse(local_storage.getItem('requestToken'));
        this.accessToken = await getAccessToken(this.keyConfig, requestToken, code);
        local_storage.setItem("accessToken", JSON.stringify(this.accessToken));
    }

    async next(): Promise<IteratorResult<Tick>> {
        while(true) {
            try {
                const [nil, quotes, balance] = await Promise.all([
                    delay(this.sleepDuration),
                    this.getQuotes(),
                    Promise.resolve(0)//this.getBalance()
                ])

                const isExtHours = quotes.QuoteData.map(q => q.All.ExtendedHourQuoteDetail !== undefined).reduce((acc,cur) => acc || cur, false)
                this.hadOpenHours = this.hadOpenHours || !isExtHours
                const done = this.hadOpenHours && isExtHours
                return {
                    value: {balance: balance, quotes: quotes},
                    done: done
                }
            } catch (e) {
                console.error(e)
            }
        }
    }

    getBalance(): Promise<number> {
        return getBalance(this.accountIdKey, { instType:"BROKERAGE", realTimeNAV:true }, this.keyConfig, this.accessToken)
        .then(res => res.Computed.RealTimeValues.totalAccountValue)
    }

    getQuotes(): Promise<QuoteResponse> {
        return getQuotes(this.watchList, { detailFlag: 'ALL' }, this.keyConfig, this.accessToken)
    }

    async createOrder(symbol:string, shares:number, limit:number, toOpen:boolean) {

    }
}

export async function runBot(
    broker:Broker,
    onBalance: ((balance: number) => Promise<void>) | null,
    onQuotes: ((quotes: QuoteResponse) => Promise<void>) | null
    ) {
        try {
            await broker.connect()
        } catch (error) {
            console.error(error)
            return
        }

        for await (const tick of broker) {
            try {
                if (onBalance !== null) await onBalance(tick.balance)
                if (onQuotes !== null) await onQuotes(tick.quotes)
            } catch (error) {
                console.error(error)
            }
        }
}
