#ifndef NIKON_H
#define NIKON_H

#include <NimBLERemoteCharacteristic.h>

#include "Blowfish.h"
#include "Camera.h"
#include "Scan.h"

namespace Furble {
/**
 * Nikon Coolpix B600 / Z-series.
 */
class Nikon: public Camera, public NimBLEScanCallbacks {
 public:
  Nikon(const void *data, size_t len);
  Nikon(const NimBLEAdvertisedDevice *pDevice);
  ~Nikon();

  /**
   * Determine if the advertised BLE device is a Nikon.
   */
  static bool matches(const NimBLEAdvertisedDevice *pDevice);

  void shutterPress(void) override;
  void shutterRelease(void) override;
  void focusPress(void) override;
  void focusRelease(void) override;
  void updateGeoData(const gps_t &gps, const timesync_t &timesync) override;
  size_t getSerialisedBytes(void) const override;
  bool serialise(void *buffer, size_t bytes) const override;

  // Smart-path public helpers
  bool remoteEnable(bool enable);
  bool writeCurrentTime(const timesync_t &timesync);
 protected:
  bool _connect(void) override final;
  void _disconnect(void) override final;

 private:
  class Pairing {
   public:
    enum class Type {
      REMOTE,
      SMART_DEVICE,
    };

    /** Identifier. */
    typedef struct __attribute__((packed)) _id_t {
      uint32_t device;  // sent in manufacturer data in reconnect
      uint32_t nonce;
    } id_t;

    /** Pairing message. */
    typedef struct __attribute__((packed)) _msg_t {
      uint8_t stage;
      union {
        struct __attribute__((packed)) {
          uint32_t timestampH;
          uint32_t timestampL;
        };
        uint64_t timestamp;
      };
      union {
        Pairing::id_t id;
        char serial[8];
      };
    } msg_t;

    virtual const msg_t *processMessage(const msg_t &msg) = 0;
    const msg_t *getMessage(void) const;
    Type getType(void) const;

   protected:
    Pairing(const Pairing::Type type, const uint64_t timestamp, const Pairing::id_t id);

    msg_t *m_Msg = nullptr;
    std::array<msg_t, 5> m_Stage;

   private:
    const Pairing::Type m_Type;
  };

  class RemotePairing: public Pairing {
   public:
    RemotePairing(const uint64_t timestamp, const Pairing::id_t &id);

    const msg_t *processMessage(const msg_t &msg) final;
  };

  class SmartPairing: public Pairing, Blowfish {
   public:
    SmartPairing(const uint64_t timestamp, const Pairing::id_t id);

    const msg_t *processMessage(const msg_t &msg) final;

    std::array<uint32_t, 2> hash(const uint32_t *src, size_t len) const;

   private:
    void scramble(uint32_t *pL, uint32_t *pR) const;
    int8_t findSaltIndex(const msg_t &msg);

    static const std::vector<uint8_t> KEY;
    static const std::array<std::array<uint32_t, 2>, 8> SALT;
    int8_t m_Salt = -1;
    // Selected at runtime after stage-2 validation: true = swapped 32-bit words.
    bool m_UseSwappedWords = true;
  };

  static constexpr uint16_t COMPANY_ID = 0x0399;

  /** Connect saved advertised manufacturer data. */
  typedef struct __attribute__((packed)) _nikon_adv_t {
    uint16_t companyID;
    uint32_t device;
    uint8_t zero;
  } nikon_adv_t;

  /** Time synchronisation. */
  typedef struct __attribute__((packed)) _nikon_time_t {
    uint16_t year;
    uint8_t month;
    uint8_t day;
    uint8_t hour;
    uint8_t minute;
    uint8_t second;
  } nikon_time_t;

  // 10 bytes
  typedef struct __attribute__((packed)) _timesync_msg_t {
    nikon_time_t time;
    uint8_t dst_offset;
    uint8_t tz_offset_hours;
    uint8_t tz_offset_minutes;
  } timesync_msg_t;

  // 41 bytes
  /** Location synchronisation. */
  typedef struct __attribute__((packed)) _nikon_geo_t {
    uint16_t header;             // 0x7f00 = isLat | isLon | isSat | isAlt |
                                 // isPos | isGps | isMap
    uint8_t latitude_direction;  // {N|S}
    uint8_t latitude_degrees;
    uint8_t latitude_minutes;
    uint8_t latitude_submin1;     // Remaining fractional minutes(hundredths of a minute)
    uint8_t latitude_submin2;     // Remaining fractional hundredths-of-a-minute
    uint8_t longitude_direction;  // {E|W}
    uint8_t longitude_degrees;
    uint8_t longitude_minutes;
    uint8_t longitude_submin1;  // Remaining fractional minutes(hundredths of a minute)
    uint8_t longitude_submin2;  // Remaining fractional hundredths-of-a-minute
    uint8_t satellites;         // no. of satellites
    uint8_t altitude_ref;       // P=0x50 for positive, M=0x4D for negative altitude
    uint16_t altitude;
    nikon_time_t time;
    uint8_t subseconds;
    uint8_t valid;        // 0x01 == valid
    uint8_t standard[6];  // WGS-84
    uint8_t pad[10];
  } nikon_geo_t;

  /**
   * Non-volatile storage type.
   */
  typedef struct _nikon_t {
    char name[MAX_NAME]; /** Human readable device name. */
    uint64_t address;    /** Device MAC address. */
    uint8_t type;        /** Address type. */
    Pairing::id_t id;    /** Unique identifiers. */
  } nikon_t;

  // Re-pair scan time
  static constexpr uint32_t SCAN_TIME_MS = 60000;

  // -----------------------------------------------------------------------
  // GATT handle constants (observed on Z6III, identical to Z50II).
  // Used as fallback when UUID-based lookup fails.
  //
  // Handle layout relative to SERVICE_UUID start handle 0x0040:
  //   0x0042 AUTHENTICATION (0x2000)
  //   0x0047 CLIENT_DEVICE_NAME (0x2002)
  //   0x004f CURRENT_TIME (0x2006)
  //   0x0051 LOCATION_INFORMATION (0x2007)
  //   0x0053 LSS_CONTROL_POINT (0x2008)        ← CCC 0x0054
  //   0x005a LSS_CABLE_ATTACHMENT (0x200a)     ← CCC 0x005b
  //   0x005f LSS_STATUS_FOR_CONTROL (0x2020)   ← CCC 0x0060
  //   0x0062 LSS_CONTROL_POINT_FOR_CONTROL (0x2021) ← CCC 0x0063
  // -----------------------------------------------------------------------
  static constexpr uint16_t HANDLE_LSS_CONTROL_POINT = 0x0053;
  static constexpr uint16_t HANDLE_LSS_CABLE_ATTACHMENT = 0x005a;
  static constexpr uint16_t HANDLE_LSS_STATUS_FOR_CONTROL = 0x005f;
  static constexpr uint16_t HANDLE_LSS_CONTROL_POINT_FOR_CONTROL = 0x0062;

  // -----------------------------------------------------------------------
  // Service UUID — DE00 (Nikon LSS, all Z-series and Coolpix BLE cameras)
  // -----------------------------------------------------------------------
  static const NimBLEUUID SERVICE_UUID;

  // Subscription UUIDs
  const NimBLEUUID LSS_CONTROL_POINT_UUID {0x00002008, 0x3dd4, 0x4255, 0x8d626dc7b9bd5561}; // LSS_CONTROL_POINT
  const NimBLEUUID LSS_CABLE_ATTACHMENT_UUID {0x0000200a, 0x3dd4, 0x4255, 0x8d626dc7b9bd5561}; // LSS_CABLE_ATTACHMENT

  // Stage UUIDs
  const NimBLEUUID PAIR_CHR_UUID {0x00002000, 0x3dd4, 0x4255, 0x8d626dc7b9bd5561}; // AUTHENTICATION 

  // const NimBLEUUID POWER_CONTROL_CHR_UUID {0x00002001, 0x3dd4, 0x4255, 0x8d626dc7b9bd5561};  

  // Identifier UUIDs
  const NimBLEUUID CLIENT_DEVICE_NAME_CHR_UUID {0x00002002, 0x3dd4, 0x4255, 0x8d626dc7b9bd5561};
  const NimBLEUUID SERVER_DEVICE_NAME_CHR_UUID {0x00002003, 0x3dd4, 0x4255, 0x8d626dc7b9bd5561};

  // Time and Location UUIDs
  const NimBLEUUID TIME_CHR_UUID {0x00002006, 0x3dd4, 0x4255, 0x8d626dc7b9bd5561};
  const NimBLEUUID GEO_CHR_UUID {0x00002007, 0x3dd4, 0x4255, 0x8d626dc7b9bd5561};

  const NimBLEUUID LSS_FEATURE_CHR_UUID {0x00002009, 0x3dd4, 0x4255, 0x8d626dc7b9bd5561};

  const NimBLEUUID LSS_SERIAL_NUMBER_STRING_CHR_UUID {0x0000200B, 0x3dd4, 0x4255, 0x8d626dc7b9bd5561};

  // Indicate (camera → ESP32): 16-byte smart device status.
  // Subscribed FOURTH. Snapshot cached in m_LastSmartStatus.
  // Confirmed handle 0x005f on both Z50II and Z6III, CCC: 0x0060.
  const NimBLEUUID LSS_STATUS_FOR_CONTROL_UUID {0x00002020, 0x3dd4, 0x4255, 0x8d626dc7b9bd5561};
  
  // Write/indicate (ESP32 → camera): smart device control commands.
  //   [05 00 11 00 01/00] remote enable/disable
  //   [06 00 12 00 02 vv] AF press/release
  //   [06 00 12 00 03 vv] shutter press/release
  // Subscribed FIFTH. Confirmed handle 0x0062 on both Z50II and Z6III, CCC: 0x0063.
  const NimBLEUUID LSS_CONTROL_POINT_FOR_CONTROL_UUID {0x00002021, 0x3dd4, 0x4255, 0x8d626dc7b9bd5561};
  
  // Remote UUIDs
  const NimBLEUUID REMOTE_R1_CHR_UUID {0x00002080, 0x3dd4, 0x4255, 0x8d626dc7b9bd5561};  // LSS_CATEGORY_INFO
  const NimBLEUUID REMOTE_W1_CHR_UUID {0x00002082, 0x3dd4, 0x4255, 0x8d626dc7b9bd5561};
  const NimBLEUUID REMOTE_SHUTTER_CHR_UUID {0x00002083, 0x3dd4, 0x4255, 0x8d626dc7b9bd5561};
  const NimBLEUUID REMOTE_IND1_CHR_UUID {0x00002084, 0x3dd4, 0x4255, 0x8d626dc7b9bd5561};
  const NimBLEUUID REMOTE_R2_CHR_UUID {0x00002086, 0x3dd4, 0x4255, 0x8d626dc7b9bd5561};
  const NimBLEUUID REMOTE_PAIR_CHR_UUID {0x00002087, 0x3dd4, 0x4255, 0x8d626dc7b9bd5561};

  // Notification responses
  static const std::array<uint8_t, 2> SUCCESS;
  static const std::array<uint8_t, 2> GEO;  // ? Geo request?

  // Task notification bits
  static constexpr uint32_t NOTIFY_SUCCESS = (1 << 1);

  // Control modes
  static const uint8_t MODE_SHUTTER = 0x02;
  static const uint8_t MODE_VIDEO = 0x03;
  static const uint8_t MODE_MENU = 0x04;
  static const uint8_t MODE_PLAYBACK = 0x05;

  // Control commands
  static const uint8_t CMD_PRESS = 0x02;
  static const uint8_t CMD_RELEASE = 0x00;

  // -------------------------------------------------------------------------
  // Member variables
  // -------------------------------------------------------------------------
  uint64_t m_Timestamp;
  Pairing::id_t m_ID;
  NimBLERemoteCharacteristic *m_PairChr = nullptr;
  NimBLERemoteCharacteristic *m_SmartStatusChr = nullptr;
  NimBLERemoteCharacteristic *m_SmartCmdChr = nullptr;
  std::unique_ptr<Pairing> m_Pairing = nullptr;

  // Last status indication snapshot (LSS_STATUS_FOR_CONTROL / 0x2020)
  volatile uint8_t m_LastSmartStatus[16] = {0};
  volatile uint8_t m_LastSmartStatusLen = 0;
  volatile uint32_t m_SmartStatusSeq = 0;

  QueueHandle_t m_Queue;

  bool m_RemoteEnabled = false;

  // -------------------------------------------------------------------------
  // Private smart-path helpers
  // -------------------------------------------------------------------------

  /** Smart path is active when pairing uses AUTHENTICATION (0x2000). */
  bool isSmartPairingActive(void) const;

  /**
   * Centralized smart command write with duplicate suppression.
   * Suppresses identical back-to-back writes within a 40 ms window.
   */
  bool writeSmartCommand(const uint8_t *data, size_t length);

  /** Convenience wrapper: [op 00 group 00 code value] smart command frame. */
  bool sendSmartRemoteControl(uint8_t op, uint8_t group, uint8_t code, uint8_t value);

  // Last smart command snapshot used by writeSmartCommand duplicate filter.
  std::array<uint8_t, 8> m_LastSmartCmd = {0};
  uint8_t m_LastSmartCmdLen = 0;
  uint32_t m_LastSmartCmdMs = 0;
  bool m_SendTimestamp = true;  // send timestamp once before position update
  int32_t m_LatitudeSent {0};   // store longitude to force position resend when it changes
  int32_t m_LongitudeSent {0};  // store longitude to force position resend when it changes

  // -------------------------------------------------------------------------
  // Other private helpers
  // -------------------------------------------------------------------------
  
  /**
   * Convert decimal degrees to degrees, minutes and sub-minute parts.
   */
  void degreesToDMSubMin(double value,
                         uint8_t &degrees,
                         uint8_t &minutes,
                         uint8_t &submin1,
                         uint8_t &submin2);

  /** Advertised device has requisite service UUID. */
  static bool matchesServiceUUID(const NimBLEAdvertisedDevice *pDevice);

  /**
   * Called during scanning for connection to saved device.
   */
  void onResult(const NimBLEAdvertisedDevice *pDevice) override final;
};

}  // namespace Furble
#endif
