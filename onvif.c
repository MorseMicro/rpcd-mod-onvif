/*
    rpcd onvif module
    Copyright (C) 2023  Morse Micro

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License along
	with this program; if not, write to the Free Software Foundation, Inc.,
	51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <sys/types.h>
#include <ifaddrs.h>

#include <libubus.h>
#include <rpcd/plugin.h>

#include "soapH.h"
#include "soap.nsmap"
#include "wsddapi.h"
#include "wsseapi.h"

/* Seems pretty dubious making this a global buffer that never gets freed, but this
 * appears to be the way the other rpcd plugins do it. For now, I'm going to assume
 * this means that calls to our plugin are not multi-threaded, as it does make the
 * probe a lot easier...
 */
static struct blob_buf buf;
static int probe_error;
#define URLBUF_SIZE 256
#define TOKENBUF_SIZE 256
static const int DEFAULT_PROBE_TIMEOUT_SECS = 1;
static const char *IMAGING_NAMESPACE = "http://www.onvif.org/ver20/imaging/wsdl";
static const char *MEDIA_NAMESPACE = "http://www.onvif.org/ver10/media/wsdl";

/* -----------------------------------------------------------------------------------------------
 * Shared SOAP stuff.
 */

static struct soap *my_soap_init()
{
	struct soap *soap = soap_new2(SOAP_XML_STRICT | SOAP_XML_CANONICAL | SOAP_C_UTFSTRING | SOAP_IO_KEEPALIVE, SOAP_IO_KEEPALIVE);
	soap_set_namespaces(soap, soap_namespaces);
	soap_register_plugin(soap, soap_wsse);

	/* Keep the timeout reasonably low because:
	 * - we expect calls to be on our local network
	 * - rpcd will block up for all users :(
	 */
	soap->connect_timeout = soap->recv_timeout = soap->send_timeout = 2; /* seconds */

	return soap;
}

static void my_soap_cleanup(struct soap *soap)
{
	soap_destroy(soap);
	soap_end(soap);
	soap_free(soap);
}

static int add_security(struct soap *soap, const char *username, const char *password)
{
	int result;
	result = soap_wsse_add_Timestamp(soap, "Time", 10);
	if (result != SOAP_OK) {
		return result;
	}
	result = soap_wsse_add_UsernameTokenDigest(soap, "Auth", username, password);
	if (result != SOAP_OK) {
		return result;
	}
	return SOAP_OK;
}

/* Converts a soap-y error into a ubus-y error,
 * and also shows the soap error on stderr (since ubus
 * AFAIK doesn't have any way to pass extra info... :( ))*/
enum ubus_msg_status handle_soap_error(struct soap *soap)
{
	enum ubus_msg_status status;

	soap_print_fault(soap, stderr);

	switch (soap->error) {
		case SOAP_FAULT:
		{
			struct SOAP_ENV__Code *code = soap->fault->SOAP_ENV__Code;
			if (code && code->SOAP_ENV__Subcode && code->SOAP_ENV__Subcode->SOAP_ENV__Value &&
					0 == strcmp(code->SOAP_ENV__Subcode->SOAP_ENV__Value, "\"http://www.onvif.org/ver10/error\":NotAuthorized")) {
				/* Feels like this is too complicated, but, soap? */
				status = UBUS_STATUS_PERMISSION_DENIED;
			} else {
				status = UBUS_STATUS_UNKNOWN_ERROR;
			}
			break;
		}
		case SOAP_TYPE:
		case SOAP_EMPTY:
		case SOAP_REQUIRED:
		case SOAP_PROHIBITED:
		case SOAP_OCCURS:
		case SOAP_FIXED:
			/* Some of these are probably our errors rather than the caller,
			 * but it's hard to disambiguate.
			 */
			status = UBUS_STATUS_INVALID_ARGUMENT;
			break;
		case SOAP_EOF:
		case SOAP_TCP_ERROR:
		case SOAP_UDP_ERROR:
			status = UBUS_STATUS_CONNECTION_FAILED;
		default:
			status = UBUS_STATUS_UNKNOWN_ERROR;
			break;
	}

	my_soap_cleanup(soap);

	return status;
}

/* Every time I start writing a C program I think 'don't write a macro',
 * but the error handling here was just too painful/repetitive.
 */

#define HANDLE_SOAP_ERROR(fn) \
if (SOAP_OK != (fn)) { \
	fprintf(stderr, "onvif: error on line %d calling: %s\n", __LINE__, #fn); \
	return handle_soap_error(soap);\
}

#define HANDLE_SOAP_ERROR_POINTER(x) \
if (NULL == (x)) { \
	fprintf(stderr, "onvif: error on line %d calling: %s\n", __LINE__, #x); \
	return handle_soap_error(soap);\
}

#define HANDLE_SOAP_ERROR_BOOL(x) \
if (!(x)) { \
	fprintf(stderr, "onvif: error on line %d calling: %s\n", __LINE__, #x); \
	return handle_soap_error(soap);\
}

#define HANDLE_ALLOC_ERROR(fn) \
if (0 != (fn)) { \
	fprintf(stderr, "onvif: failed to allocate space for response on line %d.\n", __LINE__); \
	my_soap_cleanup(soap); \
	return UBUS_STATUS_UNKNOWN_ERROR; \
}

#define HANDLE_ALLOC_ERROR_POINTER(res) \
if (NULL == (res)) { \
	fprintf(stderr, "onvif: failed to allocate space for response on line %d.\n", __LINE__); \
	my_soap_cleanup(soap); \
	return UBUS_STATUS_UNKNOWN_ERROR; \
}

/* -----------------------------------------------------------------------------------------------
 * WSDD (WS-Discovery) handlers - unused except for ProbeMatches.
 */

void wsdd_event_Hello(struct soap *soap, unsigned int InstanceId, const char *SequenceId, unsigned int MessageNumber, const char *MessageID, const char *RelatesTo, const char *EndpointReference, const char *Types, const char *Scopes, const char *MatchBy, const char *XAddrs, unsigned int MetadataVersion)
{ }

void wsdd_event_Bye(struct soap *soap, unsigned int InstanceId, const char *SequenceId, unsigned int MessageNumber, const char *MessageID, const char *RelatesTo, const char *EndpointReference, const char *Types, const char *Scopes, const char *MatchBy, const char *XAddrs, unsigned int *MetadataVersion)
{ }

soap_wsdd_mode wsdd_event_Probe(struct soap *soap, const char *MessageID, const char *ReplyTo, const char *Types, const char *Scopes, const char *MatchBy, struct wsdd__ProbeMatchesType *ProbeMatches)
{
	return SOAP_WSDD_ADHOC;
}

void wsdd_event_ProbeMatches(struct soap *soap, unsigned int InstanceId, const char *SequenceId, unsigned int MessageNumber, const char *MessageID, const char *RelatesTo, struct wsdd__ProbeMatchesType *ProbeMatches)
{ 
	/* The assumption is that if we're receiving this event we've already setup buf so that we can
	 * shove our responses into it.
	 */
	for (int i = 0; i < ProbeMatches->__sizeProbeMatch; ++i) {
		void *tbl = blobmsg_open_table(&buf, NULL);
		if (tbl == NULL) {
			goto error;
		}
		struct wsdd__ProbeMatchType *probe_match = &(ProbeMatches->ProbeMatch[i]);
		if (0 != blobmsg_add_string(&buf, "endpoint_reference_address", probe_match->wsa5__EndpointReference.Address)) goto error;
		if (NULL != probe_match->XAddrs) {
			if (0 != blobmsg_add_string(&buf, "device_url", probe_match->XAddrs)) goto error;
		}
		if (NULL != probe_match->Types) {
			if (0 != blobmsg_add_string(&buf, "types", probe_match->Types)) goto error;
		}
		if (NULL != probe_match->Scopes) {
			if (0 != blobmsg_add_string(&buf, "scopes", probe_match->Scopes->__item)) goto error;
		}
		blobmsg_close_table(&buf, tbl);
	}

	return;

error:
	fprintf(stderr, "onvif: failed to allocate space for probe result.\n");
	probe_error = true;
}

soap_wsdd_mode wsdd_event_Resolve(struct soap *soap, const char *MessageID, const char *ReplyTo, const char *EndpointReference, struct wsdd__ResolveMatchType *match)
{
	return SOAP_WSDD_ADHOC;
}

void wsdd_event_ResolveMatches(struct soap *soap, unsigned int InstanceId, const char * SequenceId, unsigned int MessageNumber, const char *MessageID, const char *RelatesTo, struct wsdd__ResolveMatchType *match)
{ }

int SOAP_ENV__Fault(struct soap *soap, char *faultcode, char *faultstring, char *faultactor, struct SOAP_ENV__Detail *detail, struct SOAP_ENV__Code *SOAP_ENV__Code, struct SOAP_ENV__Reason *SOAP_ENV__Reason, char *SOAP_ENV__Node, char *SOAP_ENV__Role, struct SOAP_ENV__Detail *SOAP_ENV__Detail)
{
	/* populate the fault struct from the operation arguments to print it */
	soap_fault(soap);
	/* SOAP 1.1 */
	soap->fault->faultcode = faultcode;
	soap->fault->faultstring = faultstring;
	soap->fault->faultactor = faultactor;
	soap->fault->detail = detail;
	/* SOAP 1.2 */
	soap->fault->SOAP_ENV__Code = SOAP_ENV__Code;
	soap->fault->SOAP_ENV__Reason = SOAP_ENV__Reason;
	soap->fault->SOAP_ENV__Node = SOAP_ENV__Node;
	soap->fault->SOAP_ENV__Role = SOAP_ENV__Role;
	soap->fault->SOAP_ENV__Detail = SOAP_ENV__Detail;
	/* set error */
	soap->error = SOAP_FAULT;
	/* handle or display the fault here with soap_stream_fault(soap, std::cerr); */
	/* return HTTP 202 Accepted */
	return soap_send_empty_response(soap, SOAP_OK);
}

/* -----------------------------------------------------------------------------------------------
 * Actual rpcd functions.
 */

enum {
	RPC_PROBE_MULTICAST_IFNAME,
	RPC_PROBE_MULTICAST_IP,
	RPC_PROBE_TIMEOUT_SECS,
};

static const struct blobmsg_policy rpc_probe_policy[] = {
	[RPC_PROBE_MULTICAST_IFNAME] = { .name = "multicast_ifname", .type = BLOBMSG_TYPE_STRING },
	[RPC_PROBE_MULTICAST_IP] = { .name = "multicast_ip", .type = BLOBMSG_TYPE_STRING },
	[RPC_PROBE_TIMEOUT_SECS] = { .name = "timeout_secs", .type = BLOBMSG_TYPE_INT32 },
};

enum {
	RPC_INFO_DEVICE_URL,
	RPC_INFO_USERNAME,
	RPC_INFO_PASSWORD,
};

static const struct blobmsg_policy rpc_info_policy[] = {
	[RPC_INFO_DEVICE_URL] = { .name = "device_url", .type = BLOBMSG_TYPE_STRING },
	[RPC_INFO_USERNAME] = { .name = "username", .type = BLOBMSG_TYPE_STRING },
	[RPC_INFO_PASSWORD] = { .name = "password", .type = BLOBMSG_TYPE_STRING },
};

enum {
	RPC_SET_IMAGING_IMAGING_URL,
	RPC_SET_IMAGING_USERNAME,
	RPC_SET_IMAGING_PASSWORD,
	RPC_SET_IMAGING_SOURCE_TOKEN,
	RPC_SET_IMAGING_SETTINGS,
};

static const struct blobmsg_policy rpc_set_imaging_policy[] = {
	[RPC_SET_IMAGING_IMAGING_URL] = { .name = "imaging_url", .type = BLOBMSG_TYPE_STRING },
	[RPC_SET_IMAGING_USERNAME] = { .name = "username", .type = BLOBMSG_TYPE_STRING },
	[RPC_SET_IMAGING_PASSWORD] = { .name = "password", .type = BLOBMSG_TYPE_STRING },
	[RPC_SET_IMAGING_SOURCE_TOKEN] = { .name = "source_token", .type = BLOBMSG_TYPE_STRING },
	[RPC_SET_IMAGING_SETTINGS] = { .name = "settings", .type = BLOBMSG_TYPE_TABLE },
};

enum {
	SETTINGS_BRIGHTNESS,
	SETTINGS_CONTRAST,
};

static const struct blobmsg_policy imaging_settings_policy[] = {
	[SETTINGS_BRIGHTNESS] = { .name = "brightness", .type = BLOBMSG_TYPE_DOUBLE },
	[SETTINGS_CONTRAST] = { .name = "contrast", .type = BLOBMSG_TYPE_DOUBLE },
};

enum {
	RPC_SET_ENCODER_MEDIA_URL,
	RPC_SET_ENCODER_USERNAME,
	RPC_SET_ENCODER_PASSWORD,
	RPC_SET_ENCODER_ENCODER_TOKEN,
	RPC_SET_ENCODER_CONFIG,
};

static const struct blobmsg_policy rpc_set_encoder_policy[] = {
	[RPC_SET_ENCODER_MEDIA_URL] = { .name = "media_url", .type = BLOBMSG_TYPE_STRING },
	[RPC_SET_ENCODER_USERNAME] = { .name = "username", .type = BLOBMSG_TYPE_STRING },
	[RPC_SET_ENCODER_PASSWORD] = { .name = "password", .type = BLOBMSG_TYPE_STRING },
	[RPC_SET_ENCODER_ENCODER_TOKEN] = { .name = "encoder_token", .type = BLOBMSG_TYPE_STRING },
	[RPC_SET_ENCODER_CONFIG] = { .name = "config", .type = BLOBMSG_TYPE_TABLE },
};

enum {
	CONFIG_ENCODING,
	CONFIG_PROFILE,
	CONFIG_QUALITY,
	CONFIG_GOVLENGTH,
	CONFIG_FRAMERATE,
	CONFIG_BITRATE,
	CONFIG_RESOLUTION,
};

static const struct blobmsg_policy encoder_config_policy[] = {
	[CONFIG_ENCODING] = { .name = "encoding", .type = BLOBMSG_TYPE_STRING },
	[CONFIG_PROFILE] = { .name = "profile", .type = BLOBMSG_TYPE_STRING },
	[CONFIG_QUALITY] = { .name = "quality", .type = BLOBMSG_TYPE_INT32 },
	[CONFIG_GOVLENGTH] = { .name = "govlength", .type = BLOBMSG_TYPE_INT32 },
	[CONFIG_FRAMERATE] = { .name = "framerate", .type = BLOBMSG_TYPE_INT32 },
	[CONFIG_BITRATE] = { .name = "bitrate", .type = BLOBMSG_TYPE_INT32 },
	[CONFIG_RESOLUTION] = { .name = "resolution", .type = BLOBMSG_TYPE_TABLE },
};

enum {
	RESOLUTION_WIDTH,
	RESOLUTION_HEIGHT,
};

static const struct blobmsg_policy resolution_policy[] = {
	[RESOLUTION_WIDTH] = { .name = "width", .type = BLOBMSG_TYPE_INT32 },
	[RESOLUTION_HEIGHT] = { .name = "height", .type = BLOBMSG_TYPE_INT32 },
};

enum {
	RPC_GET_STREAM_MEDIA_URL,
	RPC_GET_STREAM_USERNAME,
	RPC_GET_STREAM_PASSWORD,
	RPC_GET_STREAM_ENCODER_TOKEN,
	RPC_GET_STREAM_SOURCE_CONFIG_TOKEN,
	RPC_GET_STREAM_STREAMTYPE,
	RPC_GET_STREAM_PROTOCOL,
};

static const struct blobmsg_policy rpc_get_stream_policy[] = {
	[RPC_GET_STREAM_MEDIA_URL] = { .name = "media_url", .type = BLOBMSG_TYPE_STRING },
	[RPC_GET_STREAM_USERNAME] = { .name = "username", .type = BLOBMSG_TYPE_STRING },
	[RPC_GET_STREAM_PASSWORD] = { .name = "password", .type = BLOBMSG_TYPE_STRING },
	[RPC_GET_STREAM_ENCODER_TOKEN] = { .name = "encoder_token", .type = BLOBMSG_TYPE_STRING },
	[RPC_GET_STREAM_SOURCE_CONFIG_TOKEN] = { .name = "source_config_token", .type = BLOBMSG_TYPE_STRING },
	[RPC_GET_STREAM_STREAMTYPE] = { .name = "streamtype", .type = BLOBMSG_TYPE_STRING },
	[RPC_GET_STREAM_PROTOCOL] = { .name = "protocol", .type = BLOBMSG_TYPE_STRING },
};

const char *MULTICAST_URL = "soap.udp://239.255.255.250:3702";

static int _rpc_info_parse_args(struct blob_attr *msg, char **device_url, char **username, char **password)
{
	struct blob_attr *tb[ARRAY_SIZE(rpc_info_policy)];
	blobmsg_parse(rpc_info_policy, ARRAY_SIZE(rpc_info_policy), tb, blob_data(msg), blob_len(msg));

	if (tb[RPC_INFO_DEVICE_URL]) {
		*device_url = blobmsg_data(tb[RPC_INFO_DEVICE_URL]);
	} else {
		fprintf(stderr, "onvif: info requires device_url.\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	if (tb[RPC_INFO_USERNAME]) {
		*username = blobmsg_data(tb[RPC_INFO_USERNAME]);
	}
	if (tb[RPC_INFO_PASSWORD]) {
		*password = blobmsg_data(tb[RPC_INFO_PASSWORD]);
	}

	return UBUS_STATUS_OK;
}

/* Generate bit of rpc_info response dealing with encoder_options. */
static int _rpc_info_encoder_options(struct soap *soap, const char *username, const char *password, const char *media_url, char *config_token, void *tbl)
{
	struct _trt__GetVideoEncoderConfigurationOptions enc_config_options = {.ConfigurationToken = config_token};
	struct _trt__GetVideoEncoderConfigurationOptionsResponse enc_config_options_response;
	HANDLE_SOAP_ERROR(add_security(soap, username, password));
	HANDLE_SOAP_ERROR(soap_call___trt__GetVideoEncoderConfigurationOptions(soap, media_url, NULL, &enc_config_options, &enc_config_options_response));
	{
		void *tbl = blobmsg_open_table(&buf, "options");
		HANDLE_ALLOC_ERROR_POINTER(tbl);

		struct tt__VideoEncoderConfigurationOptions *enc_options = enc_config_options_response.Options;

		{
			void *tbl = blobmsg_open_table(&buf, "quality_range");
			HANDLE_ALLOC_ERROR_POINTER(tbl);
			HANDLE_ALLOC_ERROR(blobmsg_add_u32(&buf, "min", enc_options->QualityRange->Min));
			HANDLE_ALLOC_ERROR(blobmsg_add_u32(&buf, "max", enc_options->QualityRange->Max));
			blobmsg_close_table(&buf, tbl);
		}

		{
			void *tbl = blobmsg_open_table(&buf, "encoding");
			HANDLE_ALLOC_ERROR_POINTER(tbl);

			if (enc_options->H264 != NULL) {
				void *tbl = blobmsg_open_table(&buf, "H264");
				HANDLE_ALLOC_ERROR_POINTER(tbl);

				{
					void *tbl = blobmsg_open_array(&buf, "profile");
					HANDLE_ALLOC_ERROR_POINTER(tbl);
					for (int i = 0; i < enc_options->H264->__sizeH264ProfilesSupported; ++i) {
						enum tt__H264Profile profile = enc_options->H264->H264ProfilesSupported[i];
						HANDLE_ALLOC_ERROR(blobmsg_add_string(&buf, NULL, soap_tt__H264Profile2s(soap, profile)));
					}

					blobmsg_close_table(&buf, tbl);
				}
				{
					void *tbl = blobmsg_open_array(&buf, "resolution");
					HANDLE_ALLOC_ERROR_POINTER(tbl);
					for (int i = 0; i < enc_options->H264->__sizeResolutionsAvailable; ++i) {
						struct tt__VideoResolution *resolution = &(enc_options->H264->ResolutionsAvailable[i]);
						void *tbl = blobmsg_open_table(&buf, NULL);
						HANDLE_ALLOC_ERROR_POINTER(tbl);

						HANDLE_ALLOC_ERROR(blobmsg_add_u32(&buf, "width", resolution->Width));
						HANDLE_ALLOC_ERROR(blobmsg_add_u32(&buf, "height", resolution->Height));

						blobmsg_close_table(&buf, tbl);
					}

					blobmsg_close_table(&buf, tbl);
				}
				{
					void *tbl = blobmsg_open_table(&buf, "framerate_range");
					HANDLE_ALLOC_ERROR_POINTER(tbl);

					HANDLE_ALLOC_ERROR(blobmsg_add_u32(&buf, "min", enc_options->H264->FrameRateRange->Min));
					HANDLE_ALLOC_ERROR(blobmsg_add_u32(&buf, "max", enc_options->H264->FrameRateRange->Max));
					blobmsg_close_table(&buf, tbl);
				}
				{
					void *tbl = blobmsg_open_table(&buf, "govlength_range");
					HANDLE_ALLOC_ERROR_POINTER(tbl);

					HANDLE_ALLOC_ERROR(blobmsg_add_u32(&buf, "min", enc_options->H264->GovLengthRange->Min));
					HANDLE_ALLOC_ERROR(blobmsg_add_u32(&buf, "max", enc_options->H264->GovLengthRange->Max));
					blobmsg_close_table(&buf, tbl);
				}
				{
					void *tbl = blobmsg_open_array(&buf, "encodinginterval_range");
					HANDLE_ALLOC_ERROR_POINTER(tbl);

					HANDLE_ALLOC_ERROR(blobmsg_add_u32(&buf, "min", enc_options->H264->EncodingIntervalRange->Min));
					HANDLE_ALLOC_ERROR(blobmsg_add_u32(&buf, "max", enc_options->H264->EncodingIntervalRange->Max));
					blobmsg_close_table(&buf, tbl);
				}

				blobmsg_close_table(&buf, tbl);
			}

			blobmsg_close_table(&buf, tbl);
		}

		blobmsg_close_table(&buf, tbl);
	}

	return UBUS_STATUS_OK;
}

/* Generate parts of rpc_info response dealing with imaging service. */
static int _rpc_info_imaging(struct soap *soap, const char *username, const char *password, const char *imaging_url, char *source_token)
{
	struct _timg__GetImagingSettings imaging_settings;
	struct _timg__GetImagingSettingsResponse imaging_settings_response;
	imaging_settings.VideoSourceToken = source_token;
	HANDLE_SOAP_ERROR(add_security(soap, username, password));
	HANDLE_SOAP_ERROR(soap_call___timg__GetImagingSettings(soap, imaging_url, NULL, &imaging_settings, &imaging_settings_response));
	struct tt__ImagingSettings20 *imaging = imaging_settings_response.ImagingSettings;

	if (imaging->Brightness) {
		HANDLE_ALLOC_ERROR(blobmsg_add_double(&buf, "brightness", *(imaging->Brightness)));
	}
	if (imaging->Contrast) {
		HANDLE_ALLOC_ERROR(blobmsg_add_double(&buf, "contrast", *(imaging->Contrast)));
	}

	{
		void *tbl = blobmsg_open_table(&buf, "options");
		HANDLE_ALLOC_ERROR_POINTER(tbl);

		struct _timg__GetOptions options;
		struct _timg__GetOptionsResponse options_response;
		options.VideoSourceToken = source_token;
		HANDLE_SOAP_ERROR(add_security(soap, username, password));
		HANDLE_SOAP_ERROR(soap_call___timg__GetOptions(soap, imaging_url, NULL, &options, &options_response));

		struct tt__ImagingOptions20 *im_options = options_response.ImagingOptions;
		if (im_options->Brightness) {
			void *tbl = blobmsg_open_table(&buf, "brightness_range");
			HANDLE_ALLOC_ERROR_POINTER(tbl);

			HANDLE_ALLOC_ERROR(blobmsg_add_double(&buf, "min", im_options->Brightness->Min));
			HANDLE_ALLOC_ERROR(blobmsg_add_double(&buf, "max", im_options->Brightness->Max));
			blobmsg_close_table(&buf, tbl);
		}
		if (im_options->Contrast) {
			void *tbl = blobmsg_open_table(&buf, "contrast_range");
			HANDLE_ALLOC_ERROR_POINTER(tbl);

			HANDLE_ALLOC_ERROR(blobmsg_add_double(&buf, "min", im_options->Contrast->Min));
			HANDLE_ALLOC_ERROR(blobmsg_add_double(&buf, "max", im_options->Contrast->Max));
			blobmsg_close_table(&buf, tbl);
		}
		blobmsg_close_table(&buf, tbl);
	}

	return UBUS_STATUS_OK;
}

/* Generate parts of rpc_info response dealing with media service (i.e. encoders/source). */
static int _rpc_info_media(struct soap *soap, const char *username, const char *password, const char *media_url, const char *imaging_url)
{
	{
		void *tbl = blobmsg_open_table(&buf, "encoders");
		HANDLE_ALLOC_ERROR_POINTER(tbl);

		struct _trt__GetVideoEncoderConfigurations enc_configs;
		struct _trt__GetVideoEncoderConfigurationsResponse enc_configs_response;
		HANDLE_SOAP_ERROR(add_security(soap, username, password));
		HANDLE_SOAP_ERROR(soap_call___trt__GetVideoEncoderConfigurations(soap, media_url, NULL, &enc_configs, &enc_configs_response));
		for (int i = 0; i < enc_configs_response.__sizeConfigurations; ++i) {
			struct tt__VideoEncoderConfiguration *enc_config = &(enc_configs_response.Configurations[i]);
			void *tbl = blobmsg_open_table(&buf, enc_config->token);
			HANDLE_ALLOC_ERROR_POINTER(tbl);

			HANDLE_ALLOC_ERROR(blobmsg_add_string(&buf, "encoding", soap_tt__VideoEncoding2s(soap, enc_config->Encoding)));
			HANDLE_ALLOC_ERROR(blobmsg_add_string(&buf, "profile", soap_tt__H264Profile2s(soap, enc_config->H264->H264Profile)));
			HANDLE_ALLOC_ERROR(blobmsg_add_u32(&buf, "quality", enc_config->Quality));
			HANDLE_ALLOC_ERROR(blobmsg_add_u32(&buf, "govlength", enc_config->H264->GovLength));
			HANDLE_ALLOC_ERROR(blobmsg_add_u32(&buf, "framerate", enc_config->RateControl->FrameRateLimit));
			HANDLE_ALLOC_ERROR(blobmsg_add_u32(&buf, "bitrate", enc_config->RateControl->BitrateLimit));

			{
				struct tt__VideoResolution *resolution = enc_config->Resolution;
				void *tbl = blobmsg_open_table(&buf, "resolution");
				HANDLE_ALLOC_ERROR_POINTER(tbl);

				HANDLE_ALLOC_ERROR(blobmsg_add_u32(&buf, "width", resolution->Width));
				HANDLE_ALLOC_ERROR(blobmsg_add_u32(&buf, "height", resolution->Height));
				blobmsg_close_table(&buf, tbl);
			}

			int result = _rpc_info_encoder_options(soap, username, password, media_url, enc_config->token, tbl);
			if (result != UBUS_STATUS_OK) {
				return result;
			}

			blobmsg_close_table(&buf, tbl);
		}
		blobmsg_close_table(&buf, tbl);
		soap_destroy(soap);
		soap_end(soap);
	}

	{
		void *tbl = blobmsg_open_table(&buf, "sources");
		HANDLE_ALLOC_ERROR_POINTER(tbl);

		struct _trt__GetVideoSources sources;
		struct _trt__GetVideoSourcesResponse sources_response;
		HANDLE_SOAP_ERROR(add_security(soap, username, password));
		HANDLE_SOAP_ERROR(soap_call___trt__GetVideoSources(soap, media_url, NULL, &sources, &sources_response));

		struct _trt__GetVideoSourceConfigurations configs;
		struct _trt__GetVideoSourceConfigurationsResponse configs_response;
		HANDLE_SOAP_ERROR(add_security(soap, username, password));
		HANDLE_SOAP_ERROR(soap_call___trt__GetVideoSourceConfigurations(soap, media_url, NULL, &configs, &configs_response));

		for (int i = 0; i < sources_response.__sizeVideoSources; ++i) {
			struct tt__VideoSource *source = &(sources_response.VideoSources[i]);
			void *tbl = blobmsg_open_table(&buf, source->token);
			HANDLE_ALLOC_ERROR_POINTER(tbl);

			HANDLE_ALLOC_ERROR(blobmsg_add_u32(&buf, "framerate", source->Framerate));

			{
				struct tt__VideoResolution *resolution = source->Resolution;
				void *tbl = blobmsg_open_table(&buf, "resolution");
				HANDLE_ALLOC_ERROR_POINTER(tbl);

				HANDLE_ALLOC_ERROR(blobmsg_add_u32(&buf, "width", resolution->Width));
				HANDLE_ALLOC_ERROR(blobmsg_add_u32(&buf, "height", resolution->Height));
				blobmsg_close_table(&buf, tbl);
			}

			{
				void *tbl = blobmsg_open_table(&buf, "configs");
				HANDLE_ALLOC_ERROR_POINTER(tbl);
				for (int i = 0; i < configs_response.__sizeConfigurations; ++i) {
					struct tt__VideoSourceConfiguration *config = &(configs_response.Configurations[i]);
					if (0 == strcmp(source->token, config->SourceToken)) {
						void *tbl = blobmsg_open_table(&buf, config->token);
						HANDLE_ALLOC_ERROR_POINTER(tbl);
						{
							void *tbl = blobmsg_open_table(&buf, "bounds");
							HANDLE_ALLOC_ERROR(blobmsg_add_u32(&buf, "x", config->Bounds->x));
							HANDLE_ALLOC_ERROR(blobmsg_add_u32(&buf, "y", config->Bounds->y));
							HANDLE_ALLOC_ERROR(blobmsg_add_u32(&buf, "width", config->Bounds->width));
							HANDLE_ALLOC_ERROR(blobmsg_add_u32(&buf, "height", config->Bounds->height));
							blobmsg_close_table(&buf, tbl);
						}
						blobmsg_close_table(&buf, tbl);
					}
				}
				blobmsg_close_table(&buf, tbl);
			}

			/* source->Imaging should have the imaging settings IMO, but apparently rpos at least
			 * only provides them via the imaging service so we make a bunch more calls.
			 *
			 * Since they're tied to the VideoSourceToken, though, we put them here.
			 */
			if (imaging_url[0] != '\0') {
				void *tbl = blobmsg_open_table(&buf, "imaging");
				HANDLE_ALLOC_ERROR_POINTER(tbl);

				int result = _rpc_info_imaging(soap, username, password, imaging_url, source->token);
				if (result != UBUS_STATUS_OK) {
					return result;
				}

				blobmsg_close_table(&buf, tbl);
			}
			blobmsg_close_table(&buf, tbl);
		}
		blobmsg_close_table(&buf, tbl);
	}

	return UBUS_STATUS_OK;
}

/**
 * Get all the info about an ONVIF camera.
 *
 * This makes many API calls, and is the only call here which returns
 * information about the current configuration.
 *
 * See README.md for message format.
 */
static int
rpc_info(struct ubus_context *ctx, struct ubus_object *obj,
         struct ubus_request_data *req, const char *method,
         struct blob_attr *msg)
{
	char *username = "";
	char *password = "";
	char *device_url = "";
	char media_url[URLBUF_SIZE] = "\0";
	char imaging_url[URLBUF_SIZE] = "\0";

	int result = _rpc_info_parse_args(msg, &device_url, &username, &password);
	if (UBUS_STATUS_OK != result) {
		return result;
	}

	struct soap *soap = my_soap_init();
	if (soap == NULL) {
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	HANDLE_ALLOC_ERROR(blob_buf_init(&buf, 0));

	struct _tds__GetHostname hostname;
	struct _tds__GetHostnameResponse hostname_response;
	HANDLE_SOAP_ERROR(add_security(soap, username, password));
	HANDLE_SOAP_ERROR(soap_call___tds__GetHostname(soap, device_url, NULL, &hostname, &hostname_response));
	HANDLE_ALLOC_ERROR(blobmsg_add_string(&buf, "hostname", hostname_response.HostnameInformation->Name));
	soap_destroy(soap);
	soap_end(soap);

	struct _tds__GetDeviceInformation device_info;
	struct _tds__GetDeviceInformationResponse device_info_response;
	HANDLE_SOAP_ERROR(add_security(soap, username, password));
	HANDLE_SOAP_ERROR(soap_call___tds__GetDeviceInformation(soap, device_url, NULL, &device_info, &device_info_response));
	HANDLE_ALLOC_ERROR(blobmsg_add_string(&buf, "manufacturer", device_info_response.Manufacturer));
	HANDLE_ALLOC_ERROR(blobmsg_add_string(&buf, "model", device_info_response.Model));
	HANDLE_ALLOC_ERROR(blobmsg_add_string(&buf, "firmware_version", device_info_response.FirmwareVersion));
	HANDLE_ALLOC_ERROR(blobmsg_add_string(&buf, "serial_number", device_info_response.SerialNumber));
	HANDLE_ALLOC_ERROR(blobmsg_add_string(&buf, "hardware_id", device_info_response.HardwareId));
	soap_destroy(soap);
	soap_end(soap);

	struct _tds__GetServices services;
	struct _tds__GetServicesResponse services_response;
	HANDLE_SOAP_ERROR(add_security(soap, username, password));
	HANDLE_SOAP_ERROR(soap_call___tds__GetServices(soap, device_url, NULL, &services, &services_response));
	/* Copy the URLs so we can do a soap_cleanup; use static buffers since error handling is otherwise annoying. */
	for (int i = 0; i < services_response.__sizeService;++i) {
		struct tds__Service *service = &(services_response.Service[i]);
		char *target_buf;

		if (0 == strcmp(service->Namespace, IMAGING_NAMESPACE)) {
			target_buf = imaging_url;
		} else if (0 == strcmp(service->Namespace, MEDIA_NAMESPACE)) {
			target_buf = media_url;
		} else {
			continue;
		}

		strncpy(target_buf, service->XAddr, URLBUF_SIZE);
		if (target_buf[URLBUF_SIZE - 1] != '\0') {
			fprintf(stderr, "onvif: service url is more than %d bytes long.\n", URLBUF_SIZE);
			my_soap_cleanup(soap);
			return UBUS_STATUS_UNKNOWN_ERROR;
		}
	}
	soap_destroy(soap);
	soap_end(soap);

	if (imaging_url[0]) {
		HANDLE_ALLOC_ERROR(blobmsg_add_string(&buf, "imaging_url", imaging_url));

		/* NB informational queries to imaging service happens inside the
		 * video sources processing (see _rpc_info_media).
		 */
	}

	if (media_url[0]) {
		HANDLE_ALLOC_ERROR(blobmsg_add_string(&buf, "media_url", media_url));

		void *tbl = blobmsg_open_table(&buf, "media");
		HANDLE_ALLOC_ERROR_POINTER(tbl);
		int result = _rpc_info_media(soap, username, password, media_url, imaging_url);
		if (result != UBUS_STATUS_OK) {
			return result;
		}

		blobmsg_close_table(&buf, tbl);
		soap_destroy(soap);
		soap_end(soap);
	}

	ubus_send_reply(ctx, req, buf.head);

	/* We don't free buf; it just get re-used on the next init. */

	my_soap_cleanup(soap);
	return UBUS_STATUS_OK;
}

static int _get_ip_from_ifname(char *ifname, struct in_addr *sin_addr)
{
	/* Get an IP from ifname. TODO: what if there's more than one? */
	struct ifaddrs *ifa_head;

	if (getifaddrs(&ifa_head) == -1) {
		return 0;
	}

	for (struct ifaddrs *ifa = ifa_head; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET) {
			continue;
		}

		if (0 == strcmp(ifa->ifa_name, ifname)) {
			*sin_addr = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
			freeifaddrs(ifa_head);
			return 1;
		}
	}

	freeifaddrs(ifa_head);
	return 0;
}

/**
 * Probe via UDP multicast and wait for WS-Discovery responses.
 * 
 * See README.md for message format.
 */
static int
rpc_probe(struct ubus_context *ctx, struct ubus_object *obj,
          struct ubus_request_data *req, const char *method,
          struct blob_attr *msg)
{
	struct blob_attr *tb[ARRAY_SIZE(rpc_probe_policy)];
	blobmsg_parse(rpc_probe_policy, ARRAY_SIZE(rpc_probe_policy), tb, blob_data(msg), blob_len(msg));

	/* Setup soap and initial probe.
	 * Because we're using udp/multicast, we don't use our normal soap_init.
	 */
	struct soap *soap = soap_new1(SOAP_IO_UDP);
	soap_set_namespaces(soap, soap_namespaces);
	int timeout_secs = DEFAULT_PROBE_TIMEOUT_SECS;

	struct in_addr sin_addr;
	if (tb[RPC_PROBE_MULTICAST_IFNAME]) {
		if (!_get_ip_from_ifname(blobmsg_data(tb[RPC_PROBE_MULTICAST_IFNAME]), &sin_addr)) {
			fprintf(stderr, "onvif: no IP addresses associated with device name.\n");
			my_soap_cleanup(soap);
			return UBUS_STATUS_INVALID_ARGUMENT;
		}

		soap->ipv4_multicast_if = (char *)&(sin_addr);
	}
	if (tb[RPC_PROBE_MULTICAST_IP]) {
		if (1 != inet_pton(AF_INET, blobmsg_data(tb[RPC_PROBE_MULTICAST_IP]), &sin_addr)) {
			return UBUS_STATUS_INVALID_ARGUMENT;
		}

		soap->ipv4_multicast_if = (char *)&(sin_addr);
	}
	if (tb[RPC_PROBE_TIMEOUT_SECS]) {
		timeout_secs = blobmsg_get_u32(tb[RPC_PROBE_TIMEOUT_SECS]);
	}

	HANDLE_SOAP_ERROR_BOOL(soap_valid_socket(soap_bind(soap, NULL, 0, 1000)));

	HANDLE_SOAP_ERROR(soap_wsdd_Probe(soap, SOAP_WSDD_ADHOC, SOAP_WSDD_TO_TS, MULTICAST_URL,
	                                  soap_wsa_rand_uuid(soap), NULL, "tdn:NetworkVideoTransmitter", NULL, ""));

	HANDLE_ALLOC_ERROR(blob_buf_init(&buf, 0));

	/* Open an array for our devices when we listen to probe responses we can insert them */
	void *tbl = blobmsg_open_array(&buf, "devices");
	HANDLE_ALLOC_ERROR_POINTER(tbl);

	probe_error = false;
	HANDLE_SOAP_ERROR(soap_wsdd_listen(soap, timeout_secs));

	blobmsg_close_table(&buf, tbl);

	my_soap_cleanup(soap);

	/* We don't free buf; it just get re-used on the next init. */

	if (probe_error) {
		/* We assume the error message was spat out by the probe event handler */
		return UBUS_STATUS_UNKNOWN_ERROR;
	} else {
		ubus_send_reply(ctx, req, buf.head);

		return UBUS_STATUS_OK;
	}
}

/**
 * Call SetImagingSettings with info in request.
 * 
 * See README.md for message format.
 */
static int
rpc_set_imaging(struct ubus_context *ctx, struct ubus_object *obj,
                struct ubus_request_data *req, const char *method,
                struct blob_attr *msg)
{
	char *username = "";
	char *password = "";
	char *imaging_url = "";
	char *source_token;

	struct blob_attr *tb[ARRAY_SIZE(rpc_set_imaging_policy)];
	blobmsg_parse(rpc_set_imaging_policy, ARRAY_SIZE(rpc_set_imaging_policy), tb, blob_data(msg), blob_len(msg));

	if (tb[RPC_SET_IMAGING_IMAGING_URL]) {
		imaging_url = blobmsg_data(tb[RPC_SET_IMAGING_IMAGING_URL]);
	} else {
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	if (tb[RPC_SET_IMAGING_USERNAME]) {
		username = blobmsg_data(tb[RPC_SET_IMAGING_USERNAME]);
	}
	if (tb[RPC_SET_IMAGING_PASSWORD]) {
		password = blobmsg_data(tb[RPC_SET_IMAGING_PASSWORD]);
	}
	if (tb[RPC_SET_IMAGING_SOURCE_TOKEN]) {
		source_token = blobmsg_data(tb[RPC_SET_IMAGING_SOURCE_TOKEN]);
	} else {
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	struct soap *soap = my_soap_init();
	if (soap == NULL) {
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	struct _timg__GetImagingSettings get_settings = {
		.VideoSourceToken = source_token,
	};
	struct _timg__GetImagingSettingsResponse get_settings_response;
	HANDLE_SOAP_ERROR(add_security(soap, username, password));
	HANDLE_SOAP_ERROR(soap_call___timg__GetImagingSettings(soap, imaging_url, NULL, &get_settings, &get_settings_response));

	struct tt__ImagingSettings20 *settings = get_settings_response.ImagingSettings;

	struct blob_attr *tb_settings[ARRAY_SIZE(imaging_settings_policy)];
	blobmsg_parse(imaging_settings_policy, ARRAY_SIZE(imaging_settings_policy), tb_settings, blobmsg_data(tb[RPC_SET_IMAGING_SETTINGS]), blobmsg_len(tb[RPC_SET_IMAGING_SETTINGS]));

	if (tb_settings[SETTINGS_BRIGHTNESS]) {
		if (!settings->Brightness) {
			HANDLE_SOAP_ERROR_POINTER(settings->Brightness = soap_new_float(soap, 1));
		}
		*(settings->Brightness) = blobmsg_get_double(tb_settings[SETTINGS_BRIGHTNESS]);
	}

	if (tb_settings[SETTINGS_CONTRAST]) {
		if (!settings->Contrast) {
			HANDLE_SOAP_ERROR_POINTER(settings->Contrast = soap_new_float(soap, 1));
		}
		*(settings->Contrast) = blobmsg_get_double(tb_settings[SETTINGS_CONTRAST]);
	}

	struct _timg__SetImagingSettings set_settings = {
		.VideoSourceToken = source_token,
		.ImagingSettings = settings,
	};
	struct _timg__SetImagingSettingsResponse set_settings_response;
	HANDLE_SOAP_ERROR(add_security(soap, username, password));
	HANDLE_SOAP_ERROR(soap_call___timg__SetImagingSettings(soap, imaging_url, NULL, &set_settings, &set_settings_response));

	soap_destroy(soap);
	soap_end(soap);

	my_soap_cleanup(soap);
	return UBUS_STATUS_OK;
}

static int
rpc_set_encoder(struct ubus_context *ctx, struct ubus_object *obj,
                struct ubus_request_data *req, const char *method,
                struct blob_attr *msg)
{
	/* Defaults if we're forced to construct these objects (i.e. not in existing config).
	 * We need defaults because the ubus API allows us to not set all possible config options.
	 * In general, this shouldn't be necessary, as an ONVIF device that supports
	 * these options would have them defined in the encoder config already.
	 */
	static const struct tt__VideoRateControl VIDEO_RATE_CONTROL_DEFAULTS = {
		.FrameRateLimit = 25,
		.BitrateLimit = 10000,
		.EncodingInterval = 1,
	};
	static const struct tt__H264Configuration H264_CONFIGURATION_DEFAULTS = {
		.GovLength = 25,
		.H264Profile = tt__H264Profile__High,
	};
	static const struct tt__Mpeg4Configuration MPEG4_CONFIGURATION_DEFAULTS = {
		.GovLength = 25,
		.Mpeg4Profile = tt__Mpeg4Profile__SP,
	};

	char *username = "";
	char *password = "";
	char *media_url = "";
	char *encoder_token;

	struct blob_attr *tb[ARRAY_SIZE(rpc_set_encoder_policy)];
	blobmsg_parse(rpc_set_encoder_policy, ARRAY_SIZE(rpc_set_encoder_policy), tb, blob_data(msg), blob_len(msg));

	if (tb[RPC_SET_ENCODER_MEDIA_URL]) {
		media_url = blobmsg_data(tb[RPC_SET_ENCODER_MEDIA_URL]);
	} else {
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	if (tb[RPC_SET_ENCODER_USERNAME]) {
		username = blobmsg_data(tb[RPC_SET_ENCODER_USERNAME]);
	}
	if (tb[RPC_SET_ENCODER_PASSWORD]) {
		password = blobmsg_data(tb[RPC_SET_ENCODER_PASSWORD]);
	}
	if (tb[RPC_SET_ENCODER_ENCODER_TOKEN]) {
		encoder_token = blobmsg_data(tb[RPC_SET_ENCODER_ENCODER_TOKEN]);
	} else {
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	struct soap *soap = my_soap_init();
	if (soap == NULL) {
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	/* ONVIF expects a complete configuration, whereas we allow
	 * setting whatever you want. So, first get the current config.
	 */
	struct _trt__GetVideoEncoderConfiguration get_encoder_configuration = {
		.ConfigurationToken = encoder_token,
	};
	struct _trt__GetVideoEncoderConfigurationResponse get_encoder_configuration_response;

	HANDLE_SOAP_ERROR(add_security(soap, username, password));
	HANDLE_SOAP_ERROR(soap_call___trt__GetVideoEncoderConfiguration(soap, media_url, NULL, &get_encoder_configuration, &get_encoder_configuration_response));

	struct tt__VideoEncoderConfiguration *conf = get_encoder_configuration_response.Configuration;

	/* Now we mutate the configuration as needed. Happily, gSOAP will help
	 * us clean up the mess as long as we don't have cycles (I hope).
	 */

	struct blob_attr *tb_config[ARRAY_SIZE(encoder_config_policy)];
	blobmsg_parse(encoder_config_policy, ARRAY_SIZE(encoder_config_policy), tb_config, blobmsg_data(tb[RPC_SET_ENCODER_CONFIG]), blobmsg_len(tb[RPC_SET_ENCODER_CONFIG]));

	if (tb_config[CONFIG_ENCODING]) {
		HANDLE_SOAP_ERROR(soap_s2tt__VideoEncoding(soap, blobmsg_data(tb_config[CONFIG_ENCODING]), &(conf->Encoding)));
	}

	if (tb_config[CONFIG_QUALITY]) {
		conf->Quality = blobmsg_get_u32(tb_config[CONFIG_QUALITY]);
	}

	if (tb_config[CONFIG_GOVLENGTH] || tb_config[CONFIG_PROFILE]) {
		switch (conf->Encoding) {
			case tt__VideoEncoding__H264:
				if (!conf->H264) {
					HANDLE_SOAP_ERROR_POINTER(conf->H264 = soap_new_tt__H264Configuration(soap, 1));
					*(conf->H264) = H264_CONFIGURATION_DEFAULTS;
				}
				if (tb_config[CONFIG_GOVLENGTH]) {
					conf->H264->GovLength = blobmsg_get_u32(tb_config[CONFIG_GOVLENGTH]);
				}
				if (tb_config[CONFIG_PROFILE]) {
					HANDLE_SOAP_ERROR(soap_s2tt__H264Profile(soap, blobmsg_data(tb_config[CONFIG_PROFILE]), &(conf->H264->H264Profile)));
				}
				break;

			case tt__VideoEncoding__MPEG4:
				if (!conf->MPEG4) {
					HANDLE_SOAP_ERROR_POINTER(conf->MPEG4 = soap_new_tt__Mpeg4Configuration(soap, 1));
					*(conf->MPEG4) = MPEG4_CONFIGURATION_DEFAULTS;
				}
				if (tb_config[CONFIG_GOVLENGTH]) {
					conf->MPEG4->GovLength = blobmsg_get_u32(tb_config[CONFIG_GOVLENGTH]);
				}
				if (tb_config[CONFIG_PROFILE]) {
					HANDLE_SOAP_ERROR(soap_s2tt__Mpeg4Profile(soap, blobmsg_data(tb_config[CONFIG_PROFILE]), &(conf->MPEG4->Mpeg4Profile)));
				}
				break;

			default:
				my_soap_cleanup(soap);
				fprintf(stderr, "onvif: attempt to set govlength/profile on JPEG encoder.\n");
				return UBUS_STATUS_INVALID_ARGUMENT;
		}
	}

	if (tb_config[CONFIG_BITRATE] || tb_config[CONFIG_FRAMERATE]) {
		if (!conf->RateControl) {
			HANDLE_SOAP_ERROR_POINTER(conf->RateControl = soap_new_tt__VideoRateControl(soap, 1));
			*(conf->RateControl) = VIDEO_RATE_CONTROL_DEFAULTS;
		}

		if (tb_config[CONFIG_FRAMERATE]) {
			conf->RateControl->FrameRateLimit = blobmsg_get_u32(tb_config[CONFIG_FRAMERATE]);
		}
		if (tb_config[CONFIG_BITRATE]) {
			conf->RateControl->BitrateLimit = blobmsg_get_u32(tb_config[CONFIG_BITRATE]);
		}
	}

	if (tb_config[CONFIG_RESOLUTION]) {
		struct blob_attr *tb_res[ARRAY_SIZE(resolution_policy)];
		blobmsg_parse(resolution_policy, ARRAY_SIZE(resolution_policy), tb_res, blobmsg_data(tb_config[CONFIG_RESOLUTION]), blobmsg_len(tb_config[CONFIG_RESOLUTION]));

		if (tb_res[RESOLUTION_WIDTH]) {
			conf->Resolution->Width = blobmsg_get_u32(tb_res[RESOLUTION_WIDTH]);
		}
		if (tb_res[RESOLUTION_HEIGHT]) {
			conf->Resolution->Height = blobmsg_get_u32(tb_res[RESOLUTION_HEIGHT]);
		}
	}

	/* Finally, we can make our request. Note that we just get an empty
	 * response on success.
	 */
	struct _trt__SetVideoEncoderConfiguration set_encoder_configuration = {
		.Configuration = conf,
	};
	struct _trt__SetVideoEncoderConfigurationResponse set_encoder_configuration_response;
	HANDLE_SOAP_ERROR(add_security(soap, username, password));
	HANDLE_SOAP_ERROR(soap_call___trt__SetVideoEncoderConfiguration(soap, media_url, NULL, &set_encoder_configuration, &set_encoder_configuration_response));

	soap_destroy(soap);
	soap_end(soap);

	my_soap_cleanup(soap);
	return UBUS_STATUS_OK;
}

static int
rpc_get_stream(struct ubus_context *ctx, struct ubus_object *obj,
               struct ubus_request_data *req, const char *method,
               struct blob_attr *msg)
{
	char *username = "";
	char *password = "";
	char *media_url = "";
	char *source_config_token;
	char *encoder_token;
	char profile_token_buf[TOKENBUF_SIZE];

	struct blob_attr *tb[ARRAY_SIZE(rpc_get_stream_policy)];
	blobmsg_parse(rpc_get_stream_policy, ARRAY_SIZE(rpc_get_stream_policy), tb, blob_data(msg), blob_len(msg));

	if (tb[RPC_GET_STREAM_MEDIA_URL]) {
		media_url = blobmsg_data(tb[RPC_GET_STREAM_MEDIA_URL]);
	} else {
		fprintf(stderr, "onvif: get_stream requires media_url.\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	if (tb[RPC_GET_STREAM_USERNAME]) {
		username = blobmsg_data(tb[RPC_GET_STREAM_USERNAME]);
	}
	if (tb[RPC_GET_STREAM_PASSWORD]) {
		password = blobmsg_data(tb[RPC_GET_STREAM_PASSWORD]);
	}
	if (tb[RPC_GET_STREAM_SOURCE_CONFIG_TOKEN]) {
		source_config_token = blobmsg_data(tb[RPC_GET_STREAM_SOURCE_CONFIG_TOKEN]);
	} else {
		fprintf(stderr, "onvif: get_stream requires source_config_token.\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	if (tb[RPC_GET_STREAM_ENCODER_TOKEN]) {
		encoder_token = blobmsg_data(tb[RPC_GET_STREAM_ENCODER_TOKEN]);
	} else {
		fprintf(stderr, "onvif: get_stream requires encoder_token.\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	struct soap *soap = my_soap_init();
	if (soap == NULL) {
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	/* The ONVIF getStreamURI API expects us to provide a media profile,
	 * which is basically just encoder + source. Because we pretend
	 * media profiles don't exist, we instead create one here if
	 * no existing profile matches.
	 */
	struct _trt__GetProfiles get_profiles;
	struct _trt__GetProfilesResponse get_profiles_response;
	HANDLE_SOAP_ERROR(add_security(soap, username, password));
	HANDLE_SOAP_ERROR(soap_call___trt__GetProfiles(soap, media_url, NULL, &get_profiles, &get_profiles_response));
	char *profile_token = NULL;
	for (int i = 0; i < get_profiles_response.__sizeProfiles;++i) {
		struct tt__Profile *profile = &(get_profiles_response.Profiles[i]);
		if (profile->VideoSourceConfiguration && profile->VideoEncoderConfiguration
				&& (0 == strcmp(profile->VideoSourceConfiguration->token, source_config_token))
				&& (0 == strcmp(profile->VideoEncoderConfiguration->token, encoder_token))) {
			profile_token = profile->token;
			break;
		}
	}

	/* We failed to find a profile we could use, so we'll have to create one.
	 *
	 * Because the rpos ONVIF server doesn't support this, this code
	 * has not been validated againt a real API.
	 */
	if (profile_token == NULL) {
		profile_token = soap_strdup(soap, soap_rand_uuid(soap, "rpcd-mod-onvif-"));
		struct _trt__CreateProfile create_profile = {
			.Name = "rpcd-mod-onvif automatic profile",
			.Token = profile_token,
		};
		struct _trt__CreateProfileResponse create_profile_response;
		HANDLE_SOAP_ERROR(add_security(soap, username, password));
		HANDLE_SOAP_ERROR(soap_call___trt__CreateProfile(soap, media_url, NULL, &create_profile, &create_profile_response));

		struct _trt__AddVideoEncoderConfiguration add_encoder = {
			.ProfileToken = profile_token,
			.ConfigurationToken = encoder_token,
		};
		struct _trt__AddVideoEncoderConfigurationResponse add_encoder_response;
		HANDLE_SOAP_ERROR(add_security(soap, username, password));
		HANDLE_SOAP_ERROR(soap_call___trt__AddVideoEncoderConfiguration(soap, media_url, NULL, &add_encoder, &add_encoder_response));

		struct _trt__AddVideoSourceConfiguration add_source = {
			.ProfileToken = profile_token,
			.ConfigurationToken = source_config_token,
		};
		struct _trt__AddVideoSourceConfigurationResponse add_source_response;
		HANDLE_SOAP_ERROR(add_security(soap, username, password));
		HANDLE_SOAP_ERROR(soap_call___trt__AddVideoSourceConfiguration(soap, media_url, NULL, &add_source, &add_source_response));
	}

	/* And all we needed out of all of that was a valid profile token, so
	 * we can copy it out and dump the allocations.
	 */
	strncpy(profile_token_buf, profile_token, TOKENBUF_SIZE);
	if (profile_token_buf[TOKENBUF_SIZE - 1] != '\0') {
		fprintf(stderr, "onvif: profile token is more than %d bytes long.\n", URLBUF_SIZE);
		my_soap_cleanup(soap);
		return UBUS_STATUS_UNKNOWN_ERROR;
	}
	profile_token = profile_token_buf;

	soap_destroy(soap);
	soap_end(soap);

	/* Now we can call GetStreamURI and generate the response.
	 */
	struct tt__StreamSetup *stream_setup;
	HANDLE_SOAP_ERROR_POINTER(stream_setup = soap_new_tt__StreamSetup(soap, 1));
	if (tb[RPC_GET_STREAM_STREAMTYPE]) {
		HANDLE_SOAP_ERROR(soap_s2tt__StreamType(soap, blobmsg_data(tb[RPC_GET_STREAM_STREAMTYPE]), &(stream_setup->Stream)));
	} else {
		stream_setup->Stream = tt__StreamType__RTP_Unicast;
	}
	HANDLE_SOAP_ERROR_POINTER(stream_setup->Transport = soap_new_tt__Transport(soap, 1));
	if (tb[RPC_GET_STREAM_STREAMTYPE]) {
		HANDLE_SOAP_ERROR(soap_s2tt__TransportProtocol(soap, blobmsg_data(tb[RPC_GET_STREAM_PROTOCOL]), &(stream_setup->Transport->Protocol)));
	} else {
		stream_setup->Transport->Protocol = tt__TransportProtocol__RTSP;
	}
	stream_setup->Transport->Tunnel = NULL;

	struct _trt__GetStreamUri get_stream = {
		.StreamSetup = stream_setup,
		.ProfileToken = profile_token,
	};
	struct _trt__GetStreamUriResponse get_stream_response;
	HANDLE_SOAP_ERROR(add_security(soap, username, password));
	HANDLE_SOAP_ERROR(soap_call___trt__GetStreamUri(soap, media_url, NULL, &get_stream, &get_stream_response));

	HANDLE_ALLOC_ERROR(blob_buf_init(&buf, 0));
	HANDLE_ALLOC_ERROR(blobmsg_add_string(&buf, "stream_url", get_stream_response.MediaUri->Uri));

	ubus_send_reply(ctx, req, buf.head);

	/* We don't free buf; it just get re-used on the next init. */

	my_soap_cleanup(soap);
	return UBUS_STATUS_OK;
}

/* -----------------------------------------------------------------------------------------------
 * Register our rpcd functions.
 */

static int rpc_onvif_api_init(const struct rpc_daemon_ops *o, struct ubus_context *ctx)
{
	static const struct ubus_method onvif_methods[] = {
		UBUS_METHOD("probe", rpc_probe, rpc_probe_policy),
		UBUS_METHOD("info", rpc_info, rpc_info_policy),
		UBUS_METHOD("set_imaging", rpc_set_imaging, rpc_set_imaging_policy),
		UBUS_METHOD("set_encoder", rpc_set_encoder, rpc_set_encoder_policy),
		UBUS_METHOD("get_stream", rpc_get_stream, rpc_get_stream_policy),
	};

	static struct ubus_object_type onvif_object_type = UBUS_OBJECT_TYPE("rpcd-plugin-onvif", onvif_methods);

	static struct ubus_object onvif_object = {
		.name = "onvif",
		.type = &onvif_object_type,
		.methods = onvif_methods,
		.n_methods = ARRAY_SIZE(onvif_methods),
	};

	return ubus_add_object(ctx, &onvif_object);
}

struct rpc_plugin rpc_plugin = {
	.init = rpc_onvif_api_init
};
