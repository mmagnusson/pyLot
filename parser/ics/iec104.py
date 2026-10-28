"""IEC 60870-5-104: APCI frames and the ASDU type of each information transfer."""
from parser.ics.common import u16le

NAME = 'IEC 104'
PROTOCOL = 'IEC 60870-5-104'  # as GRASSMARLIN's fingerprints spell it

# type ID -> (acronym, description); the kind comes from the range the type is in
TYPES = {
    1: ('M_SP_NA_1', 'Single-point information'), 2: ('M_SP_TA_1', 'Single-point information with time tag'),
    3: ('M_DP_NA_1', 'Double-point information'), 4: ('M_DP_TA_1', 'Double-point information with time tag'),
    5: ('M_ST_NA_1', 'Step position information'), 6: ('M_ST_TA_1', 'Step position information with time tag'),
    7: ('M_BO_NA_1', 'Bitstring of 32 bits'), 8: ('M_BO_TA_1', 'Bitstring of 32 bits with time tag'),
    9: ('M_ME_NA_1', 'Measured value, normalized'), 10: ('M_ME_TA_1', 'Measured value, normalized with time tag'),
    11: ('M_ME_NB_1', 'Measured value, scaled'), 12: ('M_ME_TB_1', 'Measured value, scaled with time tag'),
    13: ('M_ME_NC_1', 'Measured value, short float'), 14: ('M_ME_TC_1', 'Measured value, short float with time tag'),
    15: ('M_IT_NA_1', 'Integrated totals'), 16: ('M_IT_TA_1', 'Integrated totals with time tag'),
    17: ('M_EP_TA_1', 'Event of protection equipment with time tag'),
    18: ('M_EP_TB_1', 'Packed start events of protection equipment with time tag'),
    19: ('M_EP_TC_1', 'Packed output circuit information of protection equipment with time tag'),
    20: ('M_PS_NA_1', 'Packed single-point information with status change detection'),
    21: ('M_ME_ND_1', 'Measured value, normalized without quality'),
    30: ('M_SP_TB_1', 'Single-point information with CP56 time'), 31: ('M_DP_TB_1', 'Double-point information with CP56 time'),
    32: ('M_ST_TB_1', 'Step position information with CP56 time'), 33: ('M_BO_TB_1', 'Bitstring of 32 bits with CP56 time'),
    34: ('M_ME_TD_1', 'Measured value, normalized with CP56 time'), 35: ('M_ME_TE_1', 'Measured value, scaled with CP56 time'),
    36: ('M_ME_TF_1', 'Measured value, short float with CP56 time'), 37: ('M_IT_TB_1', 'Integrated totals with CP56 time'),
    38: ('M_EP_TD_1', 'Event of protection equipment with CP56 time'),
    39: ('M_EP_TE_1', 'Packed start events of protection equipment with CP56 time'),
    40: ('M_EP_TF_1', 'Packed output circuit information of protection equipment with CP56 time'),
    45: ('C_SC_NA_1', 'Single command'), 46: ('C_DC_NA_1', 'Double command'), 47: ('C_RC_NA_1', 'Regulating step command'),
    48: ('C_SE_NA_1', 'Set point command, normalized'), 49: ('C_SE_NB_1', 'Set point command, scaled'),
    50: ('C_SE_NC_1', 'Set point command, short float'), 51: ('C_BO_NA_1', 'Bitstring of 32 bits command'),
    58: ('C_SC_TA_1', 'Single command with CP56 time'), 59: ('C_DC_TA_1', 'Double command with CP56 time'),
    60: ('C_RC_TA_1', 'Regulating step command with CP56 time'), 61: ('C_SE_TA_1', 'Set point command, normalized with CP56 time'),
    62: ('C_SE_TB_1', 'Set point command, scaled with CP56 time'), 63: ('C_SE_TC_1', 'Set point command, short float with CP56 time'),
    64: ('C_BO_TA_1', 'Bitstring of 32 bits command with CP56 time'),
    70: ('M_EI_NA_1', 'End of initialization'),
    100: ('C_IC_NA_1', 'Interrogation command'), 101: ('C_CI_NA_1', 'Counter interrogation command'),
    102: ('C_RD_NA_1', 'Read command'), 103: ('C_CS_NA_1', 'Clock synchronization command'), 104: ('C_TS_NA_1', 'Test command'),
    105: ('C_RP_NA_1', 'Reset process command'), 106: ('C_CD_NA_1', 'Delay acquisition command'),
    107: ('C_TS_TA_1', 'Test command with CP56 time'),
    110: ('P_ME_NA_1', 'Parameter of measured value, normalized'), 111: ('P_ME_NB_1', 'Parameter of measured value, scaled'),
    112: ('P_ME_NC_1', 'Parameter of measured value, short float'), 113: ('P_AC_NA_1', 'Parameter activation'),
    120: ('F_FR_NA_1', 'File ready'), 121: ('F_SR_NA_1', 'Section ready'), 122: ('F_SC_NA_1', 'Call directory, select file, call file, call section'),
    123: ('F_LS_NA_1', 'Last section, last segment'), 124: ('F_AF_NA_1', 'Acknowledge file, acknowledge section'),
    125: ('F_SG_NA_1', 'Segment'), 126: ('F_DR_TA_1', 'Directory'), 127: ('F_SC_NB_1', 'Query log'),
}
SET_POINTS = {48, 49, 50, 51, 61, 62, 63, 64}
KINDS = {100: 'read', 101: 'read', 102: 'read', 103: 'write', 104: 'diagnostic', 105: 'control', 106: 'diagnostic',
         107: 'diagnostic', 110: 'write', 111: 'write', 112: 'write', 113: 'write'}
U_FUNCTIONS = {0x07: 'STARTDT act', 0x13: 'STOPDT act'}  # TESTFR keep-alives and confirmations aren't worth listing
ACTIVATION, DEACTIVATION = 6, 8
BROADCAST_ADDRESS = 0xFFFF

def kind_of(type_id):
    if type_id < 45 or type_id == 70:
        return 'data'
    if type_id < 70:
        return 'write' if type_id in SET_POINTS else 'control'
    if type_id >= 120:
        return 'program'
    return KINDS.get(type_id, 'other')

def frame_length(data):
    if data[0] != 0x68:
        return -1
    if len(data) < 2:
        return 0
    return 2 + data[1] if 4 <= data[1] <= 253 else -1

def decode(frame, out):
    if out.request is None:
        return
    control = frame[2]
    out.roles('MASTER', 'SLAVE')  # the controlling station connects to the controlled one
    if control & 0x03 == 0x03:
        if control in U_FUNCTIONS:
            out.op(U_FUNCTIONS[control], 'session', out.client, out.server)
        return
    if control & 0x01 or len(frame) < 12:
        return  # S-format acknowledgement, or no ASDU
    type_id, cause, address = frame[6], frame[8] & 0x3F, u16le(frame, 10)
    negative = frame[8] & 0x40
    if address != BROADCAST_ADDRESS:
        out.fact(out.server, 'IEC104Address', address)
    acronym, description = TYPES.get(type_id, (f'Type {type_id}', 'unknown type'))
    name, kind = f'{acronym} {description}', kind_of(type_id)
    # Listed under the connection's controlling and controlled station, whichever of them sent it
    if kind == 'data':
        out.op(name, kind, out.client, out.server)
    elif negative:
        out.op(f'Negative confirmation: {name}', 'error', out.client, out.server)
    elif cause in (ACTIVATION, DEACTIVATION) or kind == 'program':
        out.op(name if cause != DEACTIVATION else f'Deactivate {name}', kind, out.client, out.server)
