UAF: Conformance Testing API
============================


To perform conformance testing, server vendor must implement standardised API adapter. This document describes all API endpoints and their behaviour. This document is based and fully compliant with [Client and API specification](https://fidoalliance.org/specs/fido-uaf-v1.1-id-20170202/fido-uaf-client-api-transport-v1.1-id-20170202.html).

If you have any question, issue or suggestions regarding this document, please email to [conformance-tools@fidoalliance.org](mailto:conformance-tools@fidoalliance.org)

* **Contents**
    * [IDL Definitions](#idl-definitions)
    * [Getting registration request](#getting-registration-request)
    * [Sending registration response](#sending-registration-response)
    * [Getting authentication request](#getting-authentication-request)
    * [Sending authentication response](#sending-authentication-response)
    * [Getting deregistration request](#getting-deregistration-request)

    
* **IDL Definitions**

  * [8.3.3 GetUAFRequest dictionary](https://fidoalliance.org/specs/fido-uaf-v1.1-id-20170202/fido-uaf-client-api-transport-v1.1-id-20170202.html#getuafrequest-dictionary)
    
    ```java
        dictionary GetUAFRequest {
            Operation op;
            DOMString previousRequest;
            DOMString context;
        };
    ```

  * GetUAFRequestContext
    
    ```java
        dictionary GetUAFRequestContext {
            required  DOMString username;
            DOMString           transaction;
            DOMString           deregisterAAID;
            boolean             deregisterAll;
        };
    ```

    * required DOMString `username` - a mandatory username
    * DOMString `transaction`       - Only applies to Authentication requests(op is `Auth`). If set, server must return transaction with the value of the field.
    * DOMString `deregisterAAID`    - Only applies to Deregistration requests(op is `Dereg`). If set, server must return a deregistration request for the given AAID. Server must validate AAID before sending deregistration request.
    * boolean `deregisterAll`       - Only applies to Deregistration requests(op is `Dereg`). If set to true, server must return a deregistration request, to deregister all authenticators for the given user.

  * [8.3.4 ReturnUAFRequest dictionary](https://fidoalliance.org/specs/fido-uaf-v1.1-id-20170202/fido-uaf-client-api-transport-v1.1-id-20170202.html#returnuafrequest-dictionary)
  
    ```java
        dictionary ReturnUAFRequest {
            required unsigned long statusCode;
            DOMString              uafRequest;
            Operation              op;
            long                   lifetimeMillis;
        };
    ```


  * [8.3.5 SendUAFResponse dictionary](https://fidoalliance.org/specs/fido-uaf-v1.1-id-20170202/fido-uaf-client-api-transport-v1.1-id-20170202.html#senduafresponse-dictionary)
  
    ```java
        dictionary ReturnUAFRequest {
            required unsigned long statusCode;
            DOMString              uafRequest;
            Operation              op;
            long                   lifetimeMillis;
        };
    ```

  * [8.3.7 ServerResponse Interface](https://fidoalliance.org/specs/fido-uaf-v1.1-id-20170202/fido-uaf-client-api-transport-v1.1-id-20170202.html#serverresponse-interface)
  
    ```java
        dictionary ServerResponse {
            int       statusCode;
            DOMString description;
            Token[]   additionalTokens;
            DOMString location;
            DOMString postData;
            DOMString newUAFRequest;
        };
    ```


**Getting registration request**
----

* **URL**

    * /get

* **Method:**

     * `POST`
    
*  **URL Params**

    * None

* **Data Params**

    * Example request
    ```json
        {
            "op" : "Reg",
            "context" : "{\"username\" : \"alice\"}" 
        }
    ```


* **Success Response:**

    * **Code:** 200 OK

    ```json
        {
            "statusCode" : 1200,
            "uafRequest" : "[{\"header\":{\"upv\":{\"major\":1,\"minor\":1},\"op\":\"Auth\",\"appID\":\"https://uaf.example.com\",\"serverData\":\"5s7n8-7_LDAtRIKKYqbAtTTOezVKCjl2mPorYzbpxRrZ-_3wWroMXsF_pLYjNVm_l7bplAx4bkEwK6ibil9EHGfdfKOQ1q0tyEkNJFOgqdjVmLioroxgThlj8Istpt7q\"},\"challenge\":\"HQ1VkTUQC1NJDOo6OOWdxewrb9i5WthjfKIehFxpeuU\",\"policy\":{\"accepted\":[[{\"aaid\":[\"FFFF#FFFF\"]}]]}}]"}
        }
    ```
 
* **Error Response:**

    * Example `Unauthorized`

        ```javascript
        {
            "statusCode" : 1401
        }
        ```

* **Sample Call:**

    ```javascript
        fetch('/get', {
            method  : 'POST',
            credentials : 'same-origin',
            headers : {
                'Content-Type' : 'application/json'
            },
            body: JSON.stringify({
                "op" : "Reg",
                "context" : "{\"username\" : \"alice\"}" 
            })
        }).then(function (response) {
            return response.json();
        }).then(function (json) {
            console.log(json);
        }).catch(function (err) {
            console.log({ 'status': 'failed', 'error': err });
        })
    ```


**Sending registration response**
----

* **URL**

    * /respond

* **Method:**

     * `POST`
    
*  **URL Params**

    * None

* **Data Params**

    * Example response
    ```json
        {
            "uafResponse" : "[{\"header\":{\"upv\":{\"major\":1,\"minor\":1},\"op\":\"Reg\",\"appID\":\"https://uaf.example.com/facets.json\",\"serverData\":\"ZQ_fRGDH2ar_LvrTM8JnQcl-wfnaOutiyCmpBgmMcuE\"},\"fcParams\":\"eyJmYWNldElEIjoiaHR0cHM6Ly91YWYuZXhhbXBsZS5jb20vaW5kZXguaHRtbCIsImFwcElEIjoiaHR0cHM6Ly91YWYuZXhhbXBsZS5jb20vZmFjZXRzLmpzb24iLCJjaGFsbGVuZ2UiOiJZYjM5U2RVaFUyQjAwODlwUzVMN1ZCVzhhZmRscGxudlI0QjFBbmE1dms0IiwiY2hhbm5lbEJpbmRpbmciOnt9fQ\",\"assertions\":[{\"assertionScheme\":\"UAFV1TLV\",\"assertion\":\"AT73AgM-sQALLgkARkZGRiNGQzAzDi4HAAEAAQIAAAEKLiAAbkZZjz4ysihP9vVgevgoH8SEV2JITkTxKFfsKbAiofQJLiAA2onnfjAyZ0Uc3GL4VyOEdRgIkz7q...-i2wq1FnD_svIyTyEYm_QbOYJC0GUVE-L6V7OiD8K9Z4PfiBFRO-qMdMBswDAYDVR0TBAUwAwEB_zALBgNVHQ8EBAMCBsAwCgYIKoZIzj0EAwIDSAAwRQIgWDy1Oxu8PT6diGXycY0rxb1e16omexfQ-Iv9KOg5p9cCIQCFPPCArmDh3-EyxI_OaZFPvW2kG2hQBmi9PnC-bBrfYQ\"}]}]",
            "context" : "{\"username\" : \"alice\"}" 
        }
    ```


* **Success Response:**

    * **Code:** 200 OK

    ```json
        {
            "statusCode" : 1200
        }
    ```
 
* **Error Response:**

    * Example `Bad response`

        ```javascript
        {
            "statusCode" : 1400
        }
        ```

* **Sample Call:**

    ```javascript
        fetch('/get', {
            method  : 'POST',
            credentials : 'same-origin',
            headers : {
                'Content-Type' : 'application/json'
            },
            body: JSON.stringify({
                "uafResponse" : "[{\"header\":{\"upv\":{\"major\":1,\"minor\":1},\"op\":\"Reg\",\"appID\":\"https://uaf.example.com/facets.json\",\"serverData\":\"ZQ_fRGDH2ar_LvrTM8JnQcl-wfnaOutiyCmpBgmMcuE\"},\"fcParams\":\"eyJmYWNldElEIjoiaHR0cHM6Ly91YWYuZXhhbXBsZS5jb20vaW5kZXguaHRtbCIsImFwcElEIjoiaHR0cHM6Ly91YWYuZXhhbXBsZS5jb20vZmFjZXRzLmpzb24iLCJjaGFsbGVuZ2UiOiJZYjM5U2RVaFUyQjAwODlwUzVMN1ZCVzhhZmRscGxudlI0QjFBbmE1dms0IiwiY2hhbm5lbEJpbmRpbmciOnt9fQ\",\"assertions\":[{\"assertionScheme\":\"UAFV1TLV\",\"assertion\":\"AT73AgM-sQALLgkARkZGRiNGQzAzDi4HAAEAAQIAAAEKLiAAbkZZjz4ysihP9vVgevgoH8SEV2JITkTxKFfsKbAiofQJLiAA2onnfjAyZ0Uc3GL4VyOEdRgIkz7q...-i2wq1FnD_svIyTyEYm_QbOYJC0GUVE-L6V7OiD8K9Z4PfiBFRO-qMdMBswDAYDVR0TBAUwAwEB_zALBgNVHQ8EBAMCBsAwCgYIKoZIzj0EAwIDSAAwRQIgWDy1Oxu8PT6diGXycY0rxb1e16omexfQ-Iv9KOg5p9cCIQCFPPCArmDh3-EyxI_OaZFPvW2kG2hQBmi9PnC-bBrfYQ\"}]}]",
                "context" : "{\"username\" : \"alice\"}" 
            })
        }).then(function (response) {
            return response.json();
        }).then(function (json) {
            console.log(json);
        }).catch(function (err) {
            console.log({ 'status': 'failed', 'error': err });
        })
    ```


**Getting authentication request**
----

* **URL**

    * /get

* **Method:**

     * `POST`
    
*  **URL Params**

    * None

* **Data Params**

    * Example request
    ```json
        {
            "op" : "Auth",
            "context" : "{\"username\" : \"alice\"}" 
        }
    ```

    * Example request with transaction confirmation
    ```json
        {
            "op" : "Auth",
            "context" : "{\"username\" : \"alice\", \"transaction\":\"Transfer 1000$ to Bob?\"}" 
        }
    ```

* **Success Response:**

    * **Code:** 200 OK

    ```json
        {
            "statusCode" : 1200,
            "uafRequest" : "[{\"header\":{\"upv\":{\"major\":1,\"minor\":1},\"op\":\"Auth\",\"appID\":\"https://uaf.example.com\",\"serverData\":\"5s7n8-7_LDAtRIKKYqbAtTTOezVKCjl2mPorYzbpxRrZ-_3wWroMXsF_pLYjNVm_l7bplAx4bkEwK6ibil9EHGfdfKOQ1q0tyEkNJFOgqdjVmLioroxgThlj8Istpt7q\"},\"challenge\":\"HQ1VkTUQC1NJDOo6OOWdxewrb9i5WthjfKIehFxpeuU\",\"policy\":{\"accepted\":[[{\"aaid\":[\"FFFF#FFFF\"]}]]}}]"}
        }
    ```
 
* **Error Response:**

    * Example `Unauthorized`

        ```javascript
        {
            "statusCode" : 1401
        }
        ```

* **Sample Call:**

    ```javascript
        fetch('/get', {
            method  : 'POST',
            credentials : 'same-origin',
            headers : {
                'Content-Type' : 'application/json'
            },
            body: JSON.stringify({
                "op" : "Auth",
                "context" : "{\"username\" : \"alice\"}" 
            })
        }).then(function (response) {
            return response.json();
        }).then(function (json) {
            console.log(json);
        }).catch(function (err) {
            console.log({ 'status': 'failed', 'error': err });
        })
    ```


**Sending authentication response**
----

* **URL**

    * /respond

* **Method:**

     * `POST`
    
*  **URL Params**

    * None

* **Data Params**

    * Example response
    ```json
        {
            "uafResponse" : "[{\"header\":{\"upv\":{\"major\":1,\"minor\":1},\"op\":\"Auth\",\"appID\":\"https://uaf.example.com/facets.json\",\"serverData\":\"mz0YSKHLXDd_StbbDINZaRvW3Pa6sxrNMPYp2gOs3-Y\"},\"fcParams\":\"eyJmYWNldElEIjoiaHR0cHM6Ly91YWYuZXhhbXBsZS5jb20vaW5kZXguaHRtbCIsImFwcElEIjoiaHR0cHM6Ly91YWYuZXhhbXBsZS5jb20vZmFjZXRzLmpzb24iLCJjaGFsbGVuZ2UiOiI0RDhlVXhkU3pRX1JiazdHZjBTb29LN1hyOU8yTFUtZzE1MHN0T3BLMGdvIiwiY2hhbm5lbEJpbmRpbmciOnt9fQ\",\"assertions\":[{\"assertionScheme\":\"UAFV1TLV\",\"assertion\":\"Aj7EAAQ-dgALLgkARkZGRiNGQzAzDi4FAAEAAQIADy4IAB4gsCir67EvCi4gAMYR1ZSqYuPLiNpYlomDJYGZZGQRGSlLlThqf8ZzF-k2EC4AAAkuIADaied-MDJnRRzcYvhXI4R1GAiTPuqiCrOYhNwQ8ui8_Q0uBAABAAAABi5GADBEAiDDt4-pzmEWZyakWcWGdtBQLIXSf75wL3tEjiCIry_QtQIgjw0oMlQqKOHdG2M26e1Z0bG4wGjfow_vu5zp-VkALFo\"}]}]",
            "context" : "{\"username\" : \"alice\"}" 
        }
    ```


* **Success Response:**

    * **Code:** 200 OK

    ```json
        {
            "statusCode" : 1200
        }
    ```
 
* **Error Response:**

    * Example `Bad response`

        ```javascript
        {
            "statusCode" : 1400
        }
        ```

* **Sample Call:**

    ```javascript
        fetch('/respond', {
            method  : 'POST',
            credentials : 'same-origin',
            headers : {
                'Content-Type' : 'application/json'
            },
            body: JSON.stringify({
                "uafResponse" : "[{\"header\":{\"upv\":{\"major\":1,\"minor\":1},\"op\":\"Auth\",\"appID\":\"https://uaf.example.com/facets.json\",\"serverData\":\"mz0YSKHLXDd_StbbDINZaRvW3Pa6sxrNMPYp2gOs3-Y\"},\"fcParams\":\"eyJmYWNldElEIjoiaHR0cHM6Ly91YWYuZXhhbXBsZS5jb20vaW5kZXguaHRtbCIsImFwcElEIjoiaHR0cHM6Ly91YWYuZXhhbXBsZS5jb20vZmFjZXRzLmpzb24iLCJjaGFsbGVuZ2UiOiI0RDhlVXhkU3pRX1JiazdHZjBTb29LN1hyOU8yTFUtZzE1MHN0T3BLMGdvIiwiY2hhbm5lbEJpbmRpbmciOnt9fQ\",\"assertions\":[{\"assertionScheme\":\"UAFV1TLV\",\"assertion\":\"Aj7EAAQ-dgALLgkARkZGRiNGQzAzDi4FAAEAAQIADy4IAB4gsCir67EvCi4gAMYR1ZSqYuPLiNpYlomDJYGZZGQRGSlLlThqf8ZzF-k2EC4AAAkuIADaied-MDJnRRzcYvhXI4R1GAiTPuqiCrOYhNwQ8ui8_Q0uBAABAAAABi5GADBEAiDDt4-pzmEWZyakWcWGdtBQLIXSf75wL3tEjiCIry_QtQIgjw0oMlQqKOHdG2M26e1Z0bG4wGjfow_vu5zp-VkALFo\"}]}]",
                "context" : "{\"username\" : \"alice\"}" 
            })
        }).then(function (response) {
            return response.json();
        }).then(function (json) {
            console.log(json);
        }).catch(function (err) {
            console.log({ 'status': 'failed', 'error': err });
        })
    ```


**Getting deregistration request**
----

* **URL**

    * /get

* **Method:**

     * `POST`
    
*  **URL Params**

    * None

* **Data Params**

    * Example request
    ```json
        {
            "op" : "Dereg",
            "context" : "{\"username\" : \"alice\"}" 
        }
    ```

    * Example request to deregister all users for specific authenticator
    ```json
        {
            "op" : "Dereg",
            "context" : "{\"username\" : \"alice\", \"deregisterAAID\" : \"FFFF#FFFF\"}" 
        }
    ```

    * Example request to deregister all authenticators
    ```json
        {
            "op" : "Dereg",
            "context" : "{\"username\" : \"alice\", \"deregisterAll\" : true}" 
        }
    ```

* **Success Response:**

    * **Code:** 200 OK

    ```json
        {
            "statusCode" : 1200,
            "uafRequest" : "[{\"header\":{\"op\":\"Dereg\",\"upv\":{\"major\":1,\"minor\":1},\"appID\":\"https://uaf.example.com\"},\"authenticators\":[{\"aaid\":\"ABCD#ABCD\",\"keyID\":\"ZMCPn92yHv1Ip-iCiBb6i4ADq6ZOv569KFQCvYSJfNg\"}]}]"}
        }
    ```
 
* **Error Response:**

    * Example `Unauthorized`

        ```javascript
        {
            "statusCode" : 1401
        }
        ```

* **Sample Call:**

    ```javascript
        fetch('/get', {
            method  : 'POST',
            credentials : 'same-origin',
            headers : {
                'Content-Type' : 'application/json'
            },
            body: JSON.stringify({
                "op" : "Dereg",
                "context" : "{\"username\" : \"alice\"}" 
            })
        }).then(function (response) {
            return response.json();
        }).then(function (json) {
            console.log(json);
        }).catch(function (err) {
            console.log({ 'status': 'failed', 'error': err });
        })
    ```



