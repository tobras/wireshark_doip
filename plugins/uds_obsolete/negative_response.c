// negative_response.c

#include "negative_response.h"

#include  "config.h"
#include <epan/packet.h>



static int hf_service = -1;
static int hf_response_code = -1;

static const value_string uds_services[] = {
    { 0x10, "DiagnosticSessionControl" },
    { 0x11, "ECUReset" },
    { 0x14, "ClearDiagnosticInformation" },
    { 0x19, "ReadDTCInformation" },
    { 0x22, "ReadDataByIdentifier" }, 
    { 0x23, "ReadMemoryByAddress" },
    { 0x24, "ReadScalingDataByIdentifier" },
    { 0x27, "SecurityAccess" },
    { 0x28, "CommunicationControl" },
    { 0x2A, "ReadDataByPeriodicIdentifier" },
    { 0x2C, "DynamicallyDefineDataIdentifier" },
    { 0x2E, "WriteDataByIdentifier" },
    { 0x2F, "InputOutputControlByIdentifier" },
    { 0x31, "RoutineControl" },
    { 0x34, "RequestDownload" },
    { 0x35, "RequestUpload" },
    { 0x36, "TransferData" },
    { 0x37, "RequestTransferExit" },
    { 0x3D, "WriteMemoryByAddress" },

    { 0x3E, "TesterPresent" },

    { 0x83, "AccessTimingParameter" },
    { 0x84, "SecuredDataTransmission" },
    { 0x85, "ControlDTCSetting" },
    { 0x86, "ResponseOnEvent" },
    { 0x87, "LinkControl" },


    { 0x50, "DiagnosticSessionControl Response" },
    { 0x51, "ECUReset Response" },
    { 0x54, "ClearDiagnosticInformation Response" },
    { 0x59, "ReadDTCInformation Response" },    
    { 0x62, "ReadDataByIdentifier Response" },

    { 0x63, "ReadMemoryByAddress Response" },
    { 0x64, "ReadScalingDataByIdentifier Response" },
    { 0x67, "SecurityAccess Response" },
    { 0x68, "CommunicationControl Response" },
    { 0x6A, "ReadDataByPeriodicIdentifier Response" },
    { 0x6C, "DynamicallyDefineDataIdentifier Response" },
    { 0x6E, "WriteDataByIdentifier Response" },
    { 0x6F, "InputOutputControlByIdentifier Response" },
    { 0x71, "RoutineControl Response" },
    { 0x74, "RequestDownload Response" },
    { 0x75, "RequestUpload Response" },
    { 0x76, "TransferData Response" },
    { 0x77, "RequestTransferExit Response" },
    { 0x7D, "WriteMemoryByAddress Response" },
    { 0x7F, "Negative Response" },

    { 0xC3, "AccessTimingParameter Response" },
    { 0xC4, "SecuredDataTransmission Response" },
    { 0xC5, "ControlDTCSetting Response" },
    { 0xC6, "ResponseOnEvent Response" },
    { 0xC7, "LinkControl Response" },
    { 0, NULL }
};


static const value_string response_code[] = {
  { 0x00, "positiveResponse" },
  { 0x10, "generalReject" },
  { 0x11, "serviceNotSupported" },
  { 0x12, "subFunctionNotSupported" },
  { 0x13, "incorrectMessageLengthOrInvalidFormat" },
  { 0x21, "busyRepeatRequest" },
  { 0x22, "conditionsNotCorrect" },
  { 0x24, "requestSequenceError" },
  { 0x31, "requestOutOfRange" },
  { 0x33, "securityAccessDenied" },
  { 0x35, "invalidKey" },
  { 0x36, "exceedNumberOfAttempts" },
  { 0x37, "requiredTimeDelayNotExpired" },
  { 0x70, "uploadDownloadNotAccepted" },
  { 0x71, "transferDataSuspended" },
  { 0x72, "generalProgrammingFailure" },
  { 0x73, "wrongBlockSequenceCounter" },
  { 0x78, "responsePending" },
  { 0x7E, "subFunctionNotSupportedInActiveSession" },
  { 0x7F, "serviceNotSupportedInActiveSession" },
  { 0x81, "rpmTooHigh" },
  { 0x82, "rpmTooLow" },
  { 0x83, "engineIsRunning" },
  { 0x84, "engineIsNotRunning" },
  { 0x85, "engineRunTimeTooLow" },
  { 0x86, "temperatureTooHigh" },
  { 0x87, "temperatureTooLow" },
  { 0x88, "vehicleSpeedTooHigh" },
  { 0x89, "vehicleSpeedTooLow" },
  { 0x8A, "throttle/PedalTooHigh" },
  { 0x8B, "throttle/PedalTooLow" },
  { 0x8C, "transmissionRangeNotInNeutral" },
  { 0x8D, "transmissionRangeNotInGear" },
  { 0x8F, "brakeSwitch(es)NotClosed (Brake Pedal not pressed or not applied)" },
  { 0x90, "shifterLeverNotInPark" },
  { 0x91, "torqueConverterClutchLocked" },
  { 0x92, "voltageTooHigh" },
  { 0x93, "voltageTooLow" },
  { 0, NULL }
};


gint add_negative_response_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset)
{
        guint8 service = tvb_get_guint8(tvb, offset);
	guint8 code = tvb_get_guint8(tvb, offset + 1);
	
	col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(service, uds_services, "0x%02x Unknown service"));
	col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(code, response_code, "0x%02x Unknown responseCode"));

	if (uds_tree)
	{
		proto_tree_add_item(uds_tree, hf_service, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(uds_tree, hf_response_code, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
	}

	return offset + 2;
}


void proto_register_negative_response(gint proto_uds)
{
	static hf_register_info hf_negative_response[] = 
	{
		{
			&hf_service,
			{ "Service Responding", "uds.negative_response.service",
			FT_UINT8, BASE_HEX,
			VALS(uds_services), 0x00,
			NULL, HFILL
			}
		},
		{
			&hf_response_code,
			{
				"Response Code", "uds.negative_response.responseCode",
				FT_UINT8, BASE_HEX,
				VALS(response_code), 0x00,
				NULL, HFILL
			}
		}
	};

	proto_register_field_array(proto_uds, hf_negative_response, array_length(hf_negative_response));
}

