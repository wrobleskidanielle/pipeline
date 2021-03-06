/*
 * Anchore Engine API Server
 *
 * This is the Anchore Engine API. Provides the primary external API for users of the service.
 *
 * API version: 0.1.12
 * Contact: nurmi@anchore.com
 */

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package anchore

import (
	_context "context"
	_ioutil "io/ioutil"
	_nethttp "net/http"
	_neturl "net/url"
	"github.com/antihax/optional"
)

// Linger please
var (
	_ _context.Context
)

// VulnerabilitiesApiService VulnerabilitiesApi service
type VulnerabilitiesApiService service

// QueryImagesByVulnerabilityOpts Optional parameters for the method 'QueryImagesByVulnerability'
type QueryImagesByVulnerabilityOpts struct {
    Namespace optional.String
    AffectedPackage optional.String
    Severity optional.String
    VendorOnly optional.Bool
    Page optional.Int32
    Limit optional.Int32
    XAnchoreAccount optional.String
}

/*
QueryImagesByVulnerability List images vulnerable to the specific vulnerability ID.
Returns a listing of images and their respective packages vulnerable to the given vulnerability ID
 * @param ctx _context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 * @param vulnerabilityId The ID of the vulnerability to search for within all images stored in anchore-engine (e.g. CVE-1999-0001)
 * @param optional nil or *QueryImagesByVulnerabilityOpts - Optional Parameters:
 * @param "Namespace" (optional.String) -  Filter results to images within the given vulnerability namespace (e.g. debian:8, ubuntu:14.04)
 * @param "AffectedPackage" (optional.String) -  Filter results to images with vulnable packages with the given package name (e.g. libssl)
 * @param "Severity" (optional.String) -  Filter results to vulnerable package/vulnerability with the given severity
 * @param "VendorOnly" (optional.Bool) -  Filter results to include only vulnerabilities that are not marked as invalid by upstream OS vendor data
 * @param "Page" (optional.Int32) -  The page of results to fetch. Pages start at 1
 * @param "Limit" (optional.Int32) -  Limit the number of records for the requested page. If omitted or set to 0, return all results in a single page
 * @param "XAnchoreAccount" (optional.String) -  An account name to change the resource scope of the request to that account, if permissions allow (admin only)
@return PaginatedVulnerableImageList
*/
func (a *VulnerabilitiesApiService) QueryImagesByVulnerability(ctx _context.Context, vulnerabilityId string, localVarOptionals *QueryImagesByVulnerabilityOpts) (PaginatedVulnerableImageList, *_nethttp.Response, error) {
	var (
		localVarHTTPMethod   = _nethttp.MethodGet
		localVarPostBody     interface{}
		localVarFormFileName string
		localVarFileName     string
		localVarFileBytes    []byte
		localVarReturnValue  PaginatedVulnerableImageList
	)

	// create path and map variables
	localVarPath := a.client.cfg.BasePath + "/query/images/by_vulnerability"

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := _neturl.Values{}
	localVarFormParams := _neturl.Values{}

	localVarQueryParams.Add("vulnerability_id", parameterToString(vulnerabilityId, ""))
	if localVarOptionals != nil && localVarOptionals.Namespace.IsSet() {
		localVarQueryParams.Add("namespace", parameterToString(localVarOptionals.Namespace.Value(), ""))
	}
	if localVarOptionals != nil && localVarOptionals.AffectedPackage.IsSet() {
		localVarQueryParams.Add("affected_package", parameterToString(localVarOptionals.AffectedPackage.Value(), ""))
	}
	if localVarOptionals != nil && localVarOptionals.Severity.IsSet() {
		localVarQueryParams.Add("severity", parameterToString(localVarOptionals.Severity.Value(), ""))
	}
	if localVarOptionals != nil && localVarOptionals.VendorOnly.IsSet() {
		localVarQueryParams.Add("vendor_only", parameterToString(localVarOptionals.VendorOnly.Value(), ""))
	}
	if localVarOptionals != nil && localVarOptionals.Page.IsSet() {
		localVarQueryParams.Add("page", parameterToString(localVarOptionals.Page.Value(), ""))
	}
	if localVarOptionals != nil && localVarOptionals.Limit.IsSet() {
		localVarQueryParams.Add("limit", parameterToString(localVarOptionals.Limit.Value(), ""))
	}
	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{}

	// set Content-Type header
	localVarHTTPContentType := selectHeaderContentType(localVarHTTPContentTypes)
	if localVarHTTPContentType != "" {
		localVarHeaderParams["Content-Type"] = localVarHTTPContentType
	}

	// to determine the Accept header
	localVarHTTPHeaderAccepts := []string{"application/json"}

	// set Accept header
	localVarHTTPHeaderAccept := selectHeaderAccept(localVarHTTPHeaderAccepts)
	if localVarHTTPHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHTTPHeaderAccept
	}
	if localVarOptionals != nil && localVarOptionals.XAnchoreAccount.IsSet() {
		localVarHeaderParams["x-anchore-account"] = parameterToString(localVarOptionals.XAnchoreAccount.Value(), "")
	}
	r, err := a.client.prepareRequest(ctx, localVarPath, localVarHTTPMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, localVarFormFileName, localVarFileName, localVarFileBytes)
	if err != nil {
		return localVarReturnValue, nil, err
	}

	localVarHTTPResponse, err := a.client.callAPI(r)
	if err != nil || localVarHTTPResponse == nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	localVarBody, err := _ioutil.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	if err != nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	if localVarHTTPResponse.StatusCode >= 300 {
		newErr := GenericOpenAPIError{
			body:  localVarBody,
			error: localVarHTTPResponse.Status,
		}
		if localVarHTTPResponse.StatusCode == 200 {
			var v PaginatedVulnerableImageList
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
		if localVarHTTPResponse.StatusCode == 400 {
			var v ApiErrorResponse
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	err = a.client.decode(&localVarReturnValue, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
	if err != nil {
		newErr := GenericOpenAPIError{
			body:  localVarBody,
			error: err.Error(),
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	return localVarReturnValue, localVarHTTPResponse, nil
}

// QueryVulnerabilitiesOpts Optional parameters for the method 'QueryVulnerabilities'
type QueryVulnerabilitiesOpts struct {
    AffectedPackage optional.String
    AffectedPackageVersion optional.String
    Page optional.String
    Limit optional.Int32
}

/*
QueryVulnerabilities Listing information about given vulnerability
List (w/filters) vulnerability records known by the system, with affected packages information if present
 * @param ctx _context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 * @param id The ID of the vulnerability (e.g. CVE-1999-0001)
 * @param optional nil or *QueryVulnerabilitiesOpts - Optional Parameters:
 * @param "AffectedPackage" (optional.String) -  Filter results by specified package name (e.g. sed)
 * @param "AffectedPackageVersion" (optional.String) -  Filter results by specified package version (e.g. 4.4-1)
 * @param "Page" (optional.String) -  The page of results to fetch. Pages start at 1
 * @param "Limit" (optional.Int32) -  Limit the number of records for the requested page. If omitted or set to 0, return all results in a single page
@return PaginatedVulnerabilityList
*/
func (a *VulnerabilitiesApiService) QueryVulnerabilities(ctx _context.Context, id string, localVarOptionals *QueryVulnerabilitiesOpts) (PaginatedVulnerabilityList, *_nethttp.Response, error) {
	var (
		localVarHTTPMethod   = _nethttp.MethodGet
		localVarPostBody     interface{}
		localVarFormFileName string
		localVarFileName     string
		localVarFileBytes    []byte
		localVarReturnValue  PaginatedVulnerabilityList
	)

	// create path and map variables
	localVarPath := a.client.cfg.BasePath + "/query/vulnerabilities"

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := _neturl.Values{}
	localVarFormParams := _neturl.Values{}

	localVarQueryParams.Add("id", parameterToString(id, ""))
	if localVarOptionals != nil && localVarOptionals.AffectedPackage.IsSet() {
		localVarQueryParams.Add("affected_package", parameterToString(localVarOptionals.AffectedPackage.Value(), ""))
	}
	if localVarOptionals != nil && localVarOptionals.AffectedPackageVersion.IsSet() {
		localVarQueryParams.Add("affected_package_version", parameterToString(localVarOptionals.AffectedPackageVersion.Value(), ""))
	}
	if localVarOptionals != nil && localVarOptionals.Page.IsSet() {
		localVarQueryParams.Add("page", parameterToString(localVarOptionals.Page.Value(), ""))
	}
	if localVarOptionals != nil && localVarOptionals.Limit.IsSet() {
		localVarQueryParams.Add("limit", parameterToString(localVarOptionals.Limit.Value(), ""))
	}
	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{}

	// set Content-Type header
	localVarHTTPContentType := selectHeaderContentType(localVarHTTPContentTypes)
	if localVarHTTPContentType != "" {
		localVarHeaderParams["Content-Type"] = localVarHTTPContentType
	}

	// to determine the Accept header
	localVarHTTPHeaderAccepts := []string{"application/json"}

	// set Accept header
	localVarHTTPHeaderAccept := selectHeaderAccept(localVarHTTPHeaderAccepts)
	if localVarHTTPHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHTTPHeaderAccept
	}
	r, err := a.client.prepareRequest(ctx, localVarPath, localVarHTTPMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, localVarFormFileName, localVarFileName, localVarFileBytes)
	if err != nil {
		return localVarReturnValue, nil, err
	}

	localVarHTTPResponse, err := a.client.callAPI(r)
	if err != nil || localVarHTTPResponse == nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	localVarBody, err := _ioutil.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	if err != nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	if localVarHTTPResponse.StatusCode >= 300 {
		newErr := GenericOpenAPIError{
			body:  localVarBody,
			error: localVarHTTPResponse.Status,
		}
		if localVarHTTPResponse.StatusCode == 200 {
			var v PaginatedVulnerabilityList
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
		if localVarHTTPResponse.StatusCode == 400 {
			var v ApiErrorResponse
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	err = a.client.decode(&localVarReturnValue, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
	if err != nil {
		newErr := GenericOpenAPIError{
			body:  localVarBody,
			error: err.Error(),
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	return localVarReturnValue, localVarHTTPResponse, nil
}
