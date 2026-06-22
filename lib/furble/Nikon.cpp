#include <cmath>

#include <NimBLEAddress.h>
#include <NimBLEAdvertisedDevice.h>
#include <NimBLEDevice.h>
#include <NimBLERemoteCharacteristic.h>
#include <NimBLERemoteService.h>

#include <esp_random.h>

#include "Blowfish.h"
#include "Device.h"
#include "Nikon.h"

#define NIKON_DEBUG (1)

namespace Furble {

// ---------------------------------------------------------------------------
// Smart-device identifier (8 bytes) used in stage-1 auth
// (LSS AUTHENTICATION / 0x2000).
//
// Extraction from HCI snoop:
//   tshark -r btsnoop_hci.log -Y "btatt.opcode==0x12 && btatt.handle==0x0042 &&
//   btatt.value[0]==0x01" -T fields -e btatt.value
// The last 8 bytes of the 17-byte payload are the device key.
//
// This value is camera-model-specific and must be captured per model.
//
static const std::array<uint8_t, 8> Z50II_SMART_DEVICE_KEY = {0xc4, 0xd1, 0x99, 0x67,
                                                              0x50, 0x79, 0xed, 0x5f};

static const std::array<uint8_t, 8> Z6III_SMART_DEVICE_KEY = {0xa6, 0xc1, 0x01, 0x2d,
                                                              0x8e, 0x93, 0x29, 0xe5};

const std::vector<uint8_t> Nikon::SmartPairing::KEY = {0xff, 0xff, 0xaa, 0x55,
                                                       0x11, 0x22, 0x33, 0x00};
const std::array<std::array<uint32_t, 2>, 8> Nikon::SmartPairing::SALT = {
    {
     {0x704066e4u, 0x0433d552u},
     {0xed4b8facu, 0x15f7e47bu},
     {0x24471f11u, 0x8b5ea1fcu},
     {0x05960c31u, 0x2b8c7f41u},
     {0xfda588c1u, 0xeba8b1f3u},
     {0x99166056u, 0x1bd3d550u},
     {0xcd32687fu, 0xa9e28a30u},
     {0x2a8fe834u, 0xdec7ebf4u},

     }
};
const NimBLEUUID Nikon::SERVICE_UUID {0x0000de00, 0x3dd4, 0x4255, 0x8d626dc7b9bd5561};
const std::array<uint8_t, 2> Nikon::SUCCESS = {0x01, 0x00};
const std::array<uint8_t, 2> Nikon::GEO = {0x00, 0x01};

// ---------------------------------------------------------------------------
// buildStageTimestamp — matches SnapBridge stage-1 timestamp layout:
//   low 32-bit  = monotonic ms (byte-swapped)
//   high 32-bit = random nonce (byte-swapped)
// ---------------------------------------------------------------------------
static uint64_t buildStageTimestamp(void) {
  const uint32_t tA = static_cast<uint32_t>(esp_log_timestamp());
  uint32_t sA = 0;
  esp_fill_random(&sA, sizeof(sA));
  const uint64_t low = static_cast<uint64_t>(__builtin_bswap32(tA));
  const uint64_t high = static_cast<uint64_t>(__builtin_bswap32(sA)) << 32;
  return (high | low);
}

Nikon::Pairing::Pairing(const Pairing::Type type, const uint64_t timestamp, const id_t id)
    : m_Type(type) {
  m_Stage[0].stage = 0x01;
  m_Stage[0].timestamp = timestamp;
  m_Stage[0].id = id;
  m_Stage[1].stage = 0x02;
  m_Stage[2].stage = 0x03;
  m_Stage[3].stage = 0x04;
  m_Stage[4].stage = 0x05;

  m_Msg = &m_Stage[0];
};

const Nikon::Pairing::msg_t *Nikon::Pairing::getMessage(void) const {
  return m_Msg;
}

Nikon::Pairing::Type Nikon::Pairing::getType(void) const {
  return m_Type;
}

Nikon::RemotePairing::RemotePairing(const uint64_t timestamp, const Pairing::id_t &id)
    : Pairing(Type::REMOTE, timestamp, id) {
  m_Stage[1].timestamp = 0x00;
  m_Stage[1].id = {0x00, 0x00};
  m_Stage[2].timestamp = 0x00;
  m_Stage[2].id = {0x00, 0x00};
  m_Stage[3].timestamp = 0x00;
  m_Stage[3].id = {0x00, 0x00};
  m_Stage[4].timestamp = 0x00;
  m_Stage[4].id = {0x00, 0x00};
};

const Nikon::Pairing::msg_t *Nikon::RemotePairing::processMessage(const msg_t &msg) {
  switch (msg.stage) {
    case 0:
      m_Msg = &m_Stage[0];
      return m_Msg;
    case 2:
    {
      const msg_t *expected = &m_Stage[1];
      if (memcmp(&msg, expected, sizeof(msg)) == 0) {
        m_Msg = &m_Stage[2];
        return m_Msg;
      }
    } break;
    case 4:
    {
      if (msg.timestamp == m_Stage[3].timestamp) {
        char serial[sizeof(msg.serial) + 1] = {0x00};
        strncpy(serial, msg.serial, sizeof(serial) - 1);

        ESP_LOGI(LOG_TAG, "Serial: %s", serial);
        m_Msg = &m_Stage[4];
        return m_Msg;
      }
    } break;
  }

  return nullptr;
}

Nikon::SmartPairing::SmartPairing(const uint64_t timestamp, const id_t id)
    : Pairing(Type::SMART_DEVICE, timestamp, id), Blowfish(KEY) {
  m_Stage[2].timestamp = timestamp;
}

void Nikon::SmartPairing::scramble(uint32_t *pL, uint32_t *pR) const {
  uint32_t xL = *pL;
  uint32_t xR = *pR;
  uint32_t tmp = 0;

  for (int i = 0; i < N; i++) {
    tmp = xL ^ m_P[i];
    xL = f(tmp) ^ xR;
    xR = tmp;
  }

  *pL = tmp ^ m_P[N + 1];
  *pR = xL ^ m_P[N];
}

std::array<uint32_t, 2> Nikon::SmartPairing::hash(const uint32_t *src, size_t len) const {
  uint32_t right = 0x05060708;
  uint32_t left = 0x01020304;
  uint32_t inL = 0;
  uint32_t inR = 0;

  for (uint16_t i = 0; i < len; i += 2) {
    inL = src[i] ^ left;
    inR = src[i + 1] ^ right;
    scramble(&inL, &inR);
    left = inL;
    right = inR;
  }

  return std::array<uint32_t, 2> {inL, inR};
}

int8_t Nikon::SmartPairing::findSaltIndex(const msg_t &msg) {
  // Try both swapped and native word order; remember the mode that matches.
  for (int mode = 0; mode < 2; mode++) {
    const bool useSwapped = (mode == 0);
  for (size_t i = 0; i < SALT.size(); i++) {
      const uint32_t t2h = useSwapped ? __builtin_bswap32(msg.timestampH) : msg.timestampH;
      const uint32_t t2l = useSwapped ? __builtin_bswap32(msg.timestampL) : msg.timestampL;
      const uint32_t t1h =
          useSwapped ? __builtin_bswap32(m_Stage[0].timestampH) : m_Stage[0].timestampH;
      const uint32_t t1l =
          useSwapped ? __builtin_bswap32(m_Stage[0].timestampL) : m_Stage[0].timestampL;
      std::array<uint32_t, 6> s = {SALT[i][0], SALT[i][1], t2h, t2l, t1h, t1l};
    std::array<uint32_t, 2> s2 = hash(s.data(), s.size());
      const uint32_t expectedL = useSwapped ? __builtin_bswap32(msg.id.device) : msg.id.device;
      const uint32_t expectedR = useSwapped ? __builtin_bswap32(msg.id.nonce) : msg.id.nonce;
      if ((s2[0] == expectedL) && (s2[1] == expectedR)) {
        m_UseSwappedWords = useSwapped;
        return static_cast<int8_t>(i);
    }
  }
  }
  return -1;
}

const Nikon::Pairing::msg_t *Nikon::SmartPairing::processMessage(const msg_t &msg) {
  switch (msg.stage) {
    case 0:
      m_Msg = &m_Stage[0];
      return m_Msg;
    case 2:
    {
      m_Salt = findSaltIndex(msg);
      if (m_Salt >= 0) {
        // Use the same endianness mode chosen during stage-2 verification.
        const uint32_t t1h =
            m_UseSwappedWords ? __builtin_bswap32(m_Stage[0].timestampH) : m_Stage[0].timestampH;
        const uint32_t t1l =
            m_UseSwappedWords ? __builtin_bswap32(m_Stage[0].timestampL) : m_Stage[0].timestampL;
        const uint32_t t2h = m_UseSwappedWords ? __builtin_bswap32(msg.timestampH) : msg.timestampH;
        const uint32_t t2l = m_UseSwappedWords ? __builtin_bswap32(msg.timestampL) : msg.timestampL;
        std::array<uint32_t, 6> buffer = {SALT[m_Salt][0], SALT[m_Salt][1], t1h, t1l, t2h, t2l};
        std::array<uint32_t, 2> s3 = hash(buffer.data(), buffer.size());
        m_Stage[2].id = {m_UseSwappedWords ? __builtin_bswap32(s3[0]) : s3[0],
                         m_UseSwappedWords ? __builtin_bswap32(s3[1]) : s3[1]};
        m_Msg = &m_Stage[2];

        m_Stage[3].timestamp = msg.timestamp;

        return m_Msg;
      }
    } break;
    case 4:
    {
      if ((msg.timestamp == m_Stage[3].timestamp) || (msg.timestamp == 0)) {
        char serial[sizeof(msg.serial) + 1] = {0x00};
        strncpy(serial, msg.serial, sizeof(serial) - 1);

        ESP_LOGI(LOG_TAG, "Serial: %s", serial);
        m_Msg = &m_Stage[4];
        return m_Msg;
      }
    } break;
  }

  return nullptr;
}

Nikon::Nikon(const void *data, size_t len) : Camera(Type::NIKON, PairType::SAVED) {
  if (len != sizeof(nikon_t))
    abort();

  const nikon_t *nikon = static_cast<const nikon_t *>(data);
  m_Name = std::string(nikon->name);
  m_Address = NimBLEAddress(nikon->address, nikon->type);
  m_Timestamp = buildStageTimestamp();
  memcpy(&m_ID, &nikon->id, sizeof(m_ID));
  m_Queue = xQueueCreate(3, sizeof(bool));
}

Nikon::Nikon(const NimBLEAdvertisedDevice *pDevice) : Camera(Type::NIKON, PairType::NEW) {
  m_Name = pDevice->getName();
  m_Address = pDevice->getAddress();
  m_Timestamp = buildStageTimestamp();
  esp_fill_random(&m_ID, sizeof(m_ID));
  // remote mode device ID always seems to start with 0x01
  m_ID.device &= __builtin_bswap32(0x00ffffff);
  m_ID.device |= __builtin_bswap32(0x01000000);
  m_Queue = xQueueCreate(3, sizeof(bool));
}

Nikon::~Nikon(void) {
  vQueueDelete(m_Queue);
}

bool Nikon::matchesServiceUUID(const NimBLEAdvertisedDevice *pDevice) {
  return (pDevice->haveServiceUUID() && (pDevice->getServiceUUID() == SERVICE_UUID));
}

/**
 * Determine if the advertised BLE device is a Nikon.
 *
 * During remote pairing, the camera appears to:
 * * advertise the service UUID
 * * have no manufacturer data
 */
bool Nikon::matches(const NimBLEAdvertisedDevice *pDevice) {
  return (!pDevice->haveManufacturerData() && matchesServiceUUID(pDevice));
}

void Nikon::onResult(const NimBLEAdvertisedDevice *pDevice) {
  if (pDevice->haveManufacturerData() && matchesServiceUUID(pDevice)) {
    nikon_adv_t saved = {COMPANY_ID, m_ID.device, 0x00};
    nikon_adv_t found = pDevice->getManufacturerData<nikon_adv_t>();

    if ((saved.companyID == found.companyID) && (saved.device == found.device)) {
      m_Address = pDevice->getAddress();
      bool success = true;
      xQueueSend(m_Queue, &success, 0);
    }
  }
}

bool Nikon::_connect(void) {
  bool success = false;
  m_Progress = 0;
  m_SmartStatusChr = nullptr;
  m_SmartCmdChr = nullptr;
  m_RemoteEnabled = false;
  m_SendTimestamp = true;

  if (m_PairType == PairType::SAVED || m_Paired) {
    ESP_LOGI(LOG_TAG, "Scanning");
    // need to scan for advertising camera
    auto &scan = Scan::getInstance();
    scan.clear();
    scan.start(this, SCAN_TIME_MS);
    m_Progress += 10;

    // wait up to 60s for camera to appear
    BaseType_t timeout = xQueueReceive(m_Queue, &success, pdMS_TO_TICKS(60000));
    scan.stop();

    if (timeout == pdFALSE) {
      ESP_LOGI(LOG_TAG, "Timeout waiting for camera");
      return false;
    }
  }

  ESP_LOGI(LOG_TAG, "Connecting to %s", m_Address.toString().c_str());
  bool connected = m_Client->connect(m_Address);
  // Work around esp-nimble-cpp false-negative: connect() can return false
  // even though the link is already established.
  if (!connected && m_Client->isConnected()) {
    ESP_LOGW(LOG_TAG, "connect() returned false but client is connected; treating as success");
    connected = true;
  }
  if (!connected) {
    ESP_LOGI(LOG_TAG, "Connection failed!!!");
    return false;
  }

  ESP_LOGI(LOG_TAG, "Connected");
  m_Progress += 10;

  auto *pSvc = m_Client->getService(SERVICE_UUID);
  if (pSvc == nullptr) {
    ESP_LOGE(LOG_TAG, "DE00 service not found");
    return false;
  }

  // Helper: find characteristic by handle when UUID lookup fails.
  // NimBLERemoteService has no getCharacteristicByHandle(); iterate instead.
  auto findChrByHandle = [&](uint16_t handle) -> NimBLERemoteCharacteristic * {
    for (auto *chr : pSvc->getCharacteristics(false)) {
      if (chr != nullptr && chr->getHandle() == handle) {
        return chr;
    }
    }
    return nullptr;
  };

  // ------------------------------------------------------------------
  // Try smart-device path first (LSS AUTHENTICATION / 0x2000).
  // Smart mode gives AF, GPS and time sync; remote mode only shutter.
  // ------------------------------------------------------------------
  m_PairChr = pSvc->getCharacteristic(PAIR_CHR_UUID);
  if (m_PairChr != nullptr) {
    m_Timestamp = buildStageTimestamp();
    if (m_PairType == PairType::NEW && !m_Paired) {
      // Reuse the observed SnapBridge smart-device key so the camera accepts
      // the Z50II/Z6III smart-device handshake on a fresh pairing attempt.
      //memcpy(&m_ID, Z50II_SMART_DEVICE_KEY.data(), Z50II_SMART_DEVICE_KEY.size());
      memcpy(&m_ID, Z6III_SMART_DEVICE_KEY.data(), Z6III_SMART_DEVICE_KEY.size());
    }
    m_Pairing = std::make_unique<SmartPairing>(m_Timestamp, m_ID);
    ESP_LOGI(LOG_TAG, "Connecting as smart device, subscribing to success notification");

    // ------------------------------------------------------------------
    // Step 1: Subscribe LSS_CONTROL_POINT (0x2008) notify — success cb.
    // Must be subscribed FIRST per SnapBridge trace (CCC 0x0054).
    // ------------------------------------------------------------------
    auto *pLssCtrl = pSvc->getCharacteristic(LSS_CONTROL_POINT_UUID);
    if (pLssCtrl == nullptr) {
      ESP_LOGE(LOG_TAG, "LSS_CONTROL_POINT (0x2008) not found");
      return false;
    }
    if (!pLssCtrl->subscribe(
            true,
            [this](NimBLERemoteCharacteristic *pBLERemoteCharacteristic, uint8_t *pData,
                   size_t length, bool isNotify) {
              bool rc = false;
#if NIKON_DEBUG
              ESP_LOGI(LOG_TAG, "data(not1) = %s",
                       NimBLEUtils::dataToHexString(pData, length).c_str());
#endif
              if (memcmp(pData, SUCCESS.data(), length) == 0) {
                rc = true;
              }
              xQueueSend(m_Queue, &rc, 0);
            },
            true)) {
      ESP_LOGE(LOG_TAG, "Failed to subscribe LSS_CONTROL_POINT");
      return false;
    }
    ESP_LOGI(LOG_TAG, "Subscribed to success notification!");

    // ------------------------------------------------------------------
    // Step 2: Subscribe LSS_CABLE_ATTACHMENT (0x200a) notify — no cb.
    // Must be subscribed SECOND per SnapBridge trace (CCC 0x005b).
    // Note: handle 0x0053 (LSS_CONTROL_POINT) was previously subscribed
    // here too — removed as it is identical to step 1 (same characteristic).
    // ------------------------------------------------------------------
    {
      auto *pCableAtt = pSvc->getCharacteristic(LSS_CABLE_ATTACHMENT_UUID);
      if (pCableAtt == nullptr) {
        ESP_LOGW(LOG_TAG, "LSS_CABLE_ATTACHMENT (0x200a) not found, trying handle 0x%04x",
                 HANDLE_LSS_CABLE_ATTACHMENT);
        pCableAtt = findChrByHandle(HANDLE_LSS_CABLE_ATTACHMENT);
      }
      if (pCableAtt != nullptr) {
        pCableAtt->subscribe(true, nullptr, true);
        ESP_LOGI(LOG_TAG, "Subscribed to LSS_CABLE_ATTACHMENT");
  } else {
        ESP_LOGW(LOG_TAG, "LSS_CABLE_ATTACHMENT not found (non-fatal)");
      }
    }

    // ------------------------------------------------------------------
    // Locate LSS_STATUS_FOR_CONTROL (0x2020) and
    // LSS_CONTROL_POINT_FOR_CONTROL (0x2021) or subscription in steps 4+5 below.
    // Fall back to known handles if UUID lookup fails.
    // ------------------------------------------------------------------
    m_SmartStatusChr = pSvc->getCharacteristic(LSS_STATUS_FOR_CONTROL_UUID);
    if (m_SmartStatusChr == nullptr) {
      ESP_LOGW(LOG_TAG, "UUID 0x2020 failed, trying handle 0x%04x", HANDLE_LSS_STATUS_FOR_CONTROL);
      m_SmartStatusChr = findChrByHandle(HANDLE_LSS_STATUS_FOR_CONTROL);
    }
    ESP_LOGI(LOG_TAG, "LSS_STATUS_FOR_CONTROL (0x2020): %s",
             m_SmartStatusChr ? "FOUND" : "NOT FOUND");

    m_SmartCmdChr = pSvc->getCharacteristic(LSS_CONTROL_POINT_FOR_CONTROL_UUID);
    if (m_SmartCmdChr == nullptr) {
      ESP_LOGW(LOG_TAG, "UUID 0x2021 failed, trying handle 0x%04x",
               HANDLE_LSS_CONTROL_POINT_FOR_CONTROL);
      m_SmartCmdChr = findChrByHandle(HANDLE_LSS_CONTROL_POINT_FOR_CONTROL);
    }
    ESP_LOGI(LOG_TAG, "LSS_CONTROL_POINT_FOR_CONTROL (0x2021): %s",
             m_SmartCmdChr ? "FOUND" : "NOT FOUND");

  } else {
    // Remote mode fallback.
    m_PairChr = pSvc->getCharacteristic(REMOTE_PAIR_CHR_UUID);
    if (m_PairChr == nullptr) {
      ESP_LOGE(LOG_TAG, "Neither AUTHENTICATION nor REMOTE_PAIR found");
      return false;
    }
    m_Pairing = std::make_unique<RemotePairing>(__builtin_bswap64(0x01), m_ID);
    ESP_LOGI(LOG_TAG, "Connecting as remote, subscribing to indication 1");
    auto *pInd1 = pSvc->getCharacteristic(REMOTE_IND1_CHR_UUID);
    if (pInd1 == nullptr) {
      return false;
    }
    if (!pInd1->subscribe(
            false,
            [this](NimBLERemoteCharacteristic *pBLERemoteCharacteristic, uint8_t *pData,
                   size_t length, bool isNotify) {
#if NIKON_DEBUG
              ESP_LOGI(LOG_TAG, "data(ind1) = %s",
                       NimBLEUtils::dataToHexString(pData, length).c_str());
#endif
            },
            true)) {
      return false;
    }
    ESP_LOGI(LOG_TAG, "Subscribed to indication 1!");
  }

  // ------------------------------------------------------------------
  // Step 3: Subscribe AUTHENTICATION (0x2000) indicate — stage handler.
  // Subscribed THIRD per SnapBridge trace (CCC 0x0043).
  // ------------------------------------------------------------------
  ESP_LOGI(LOG_TAG, "Subscribing to pairing indication");
  if (!m_PairChr->subscribe(
          false,
          [this](NimBLERemoteCharacteristic *pBLERemoteCharacteristic, uint8_t *pData,
                 size_t length, bool isNotify) {
#if NIKON_DEBUG
            ESP_LOGI(LOG_TAG, "data(stage) = %s",
                     NimBLEUtils::dataToHexString(pData, length).c_str());
#endif
            Nikon::Pairing::msg_t msg;
            memcpy(&msg, pData, sizeof(msg));
            auto *pMsg = this->m_Pairing->processMessage(msg);
            bool rc = (pMsg != nullptr);
            if (!rc) {
              ESP_LOGW(LOG_TAG, "Stage response mismatch");
            }
            xQueueSend(m_Queue, &rc, 0);
          },
          true)) {
    ESP_LOGE(LOG_TAG, "Failed to subscribe pairing indication");
    return false;
  }
  ESP_LOGI(LOG_TAG, "Subscribed to pairing indication!");

  // ------------------------------------------------------------------
  // Steps 4+5: Subscribe STATUS and CMD indications.
  // Subscribed FOURTH and FIFTH per SnapBridge trace.
  // ------------------------------------------------------------------
  if (m_SmartStatusChr != nullptr) {
    m_SmartStatusChr->subscribe(
        false,
        [this](NimBLERemoteCharacteristic *, uint8_t *pData, size_t length, bool) {
          // Cache the latest smart status bytes so higher-level code can gate release timing.
          const size_t copyLen = std::min<size_t>(length, sizeof(this->m_LastSmartStatus));
          for (size_t i = 0; i < copyLen; i++) {
            this->m_LastSmartStatus[i] = pData[i];
          }
          m_LastSmartStatusLen = static_cast<uint8_t>(copyLen);
          m_SmartStatusSeq = static_cast<uint32_t>(m_SmartStatusSeq + 1u);
          ESP_LOGI(LOG_TAG, "data(status) = %s",
                   NimBLEUtils::dataToHexString(pData, length).c_str());
        },
        true);
  }
  if (m_SmartCmdChr != nullptr) {
    m_SmartCmdChr->subscribe(
        false,
        [this](NimBLERemoteCharacteristic *, uint8_t *pData, size_t length, bool) {
          ESP_LOGI(LOG_TAG, "data(cmd) = %s", NimBLEUtils::dataToHexString(pData, length).c_str());
        },
        true);
  }

  success = true;

  // ------------------------------------------------------------------
  // Four-stage auth handshake
  // ------------------------------------------------------------------
  for (uint8_t stage = 0; stage < 4 && success; stage += 2) {
    const auto *msg = m_Pairing->getMessage();
    if (!m_PairChr->writeValue((const uint8_t *)msg, sizeof(*msg), true)) {
      ESP_LOGE(LOG_TAG, "Stage write failed");
      return false;
    }
#if NIKON_DEBUG
    ESP_LOGI(LOG_TAG, "sent = %s",
             NimBLEUtils::dataToHexString((const uint8_t *)msg, sizeof(*msg)).c_str());
#endif

    // wait 10s for a notification
    BaseType_t timeout = xQueueReceive(m_Queue, &success, pdMS_TO_TICKS(10000));
    if (timeout == pdFALSE) {
      success = false;
      ESP_LOGE(LOG_TAG, "Timeout waiting for stage response");
      break;
    }

    m_Progress += 5;
  }

  if (!success) {
    return false;
  }

  m_Progress += 10;

  if (m_Pairing->getType() == Pairing::Type::SMART_DEVICE) {
    // Camera may not emit an additional final-OK notification after stage 4.
    bool extraOk = false;
    if (xQueueReceive(m_Queue, &extraOk, pdMS_TO_TICKS(200)) == pdFALSE) {
      ESP_LOGI(LOG_TAG, "No post-auth final OK; continuing");
    }
  } else {
    success = true;
  }

  if (!success) {
    return false;
  }

  // ------------------------------------------------------------------
  // Post-handshake: identification + time + connection establishment
  // ------------------------------------------------------------------
  if (m_Pairing->getType() == Pairing::Type::SMART_DEVICE) {
    // Write CLIENT_DEVICE_NAME (0x2002)
    std::array<uint8_t, 32> appName {};
    const auto nameStr = Device::getStringID();
    memcpy(appName.data(), nameStr.c_str(), std::min(nameStr.size(), appName.size() - 1));
    ESP_LOGI(LOG_TAG, "Identifying as %s", nameStr.c_str());
    if (!m_Client->setValue(SERVICE_UUID, CLIENT_DEVICE_NAME_CHR_UUID,
                            {appName.data(), appName.size()}, true)) {
        ESP_LOGE(LOG_TAG, "CLIENT_DEVICE_NAME write failed");
      return false;
    }
  } else {
    // nothing more needed for remote mode
  }

  ESP_LOGI(LOG_TAG, "%s", success ? "Done!" : "Failed to receive final OK.");

  m_Progress = 100;

  return success;
}

void Nikon::shutterPress(void) {
  if (isSmartPairingActive()) {
    if (!m_RemoteEnabled && m_SmartCmdChr != nullptr) {
      remoteEnable(true);
      m_RemoteEnabled = true;
    }
    sendSmartRemoteControl(0x06, 0x12, 0x03, 0x01);
    return;
  }
  std::array<uint8_t, 2> cmd = {MODE_SHUTTER, CMD_PRESS};
  m_Client->setValue(SERVICE_UUID, REMOTE_SHUTTER_CHR_UUID, {cmd.data(), cmd.size()}, true);
}

void Nikon::shutterRelease(void) {
  if (isSmartPairingActive()) {
    sendSmartRemoteControl(0x06, 0x12, 0x03, 0x00);
    return;
  }
  std::array<uint8_t, 2> cmd = {MODE_SHUTTER, CMD_RELEASE};
  m_Client->setValue(SERVICE_UUID, REMOTE_SHUTTER_CHR_UUID, {cmd.data(), cmd.size()}, true);
}

void Nikon::focusPress(void) {
  if (isSmartPairingActive()) {
    if (!m_RemoteEnabled && m_SmartCmdChr != nullptr) {
      remoteEnable(true);
      m_RemoteEnabled = true;
    }
    sendSmartRemoteControl(0x06, 0x12, 0x02, 0x01);
  }
}

void Nikon::focusRelease(void) {
  if (isSmartPairingActive()) {
    sendSmartRemoteControl(0x06, 0x12, 0x02, 0x00);
  }
}

// ---------------------------------------------------------------------------
// Smart-path public helpers
// ---------------------------------------------------------------------------
bool Nikon::remoteEnable(bool enable) {
  if (!m_Client || !m_Client->isConnected()) {
    return false;
  }
  if (isSmartPairingActive()) {
    if (m_SmartCmdChr == nullptr) {
      return false;
    }
    std::array<uint8_t, 5> cmd = {0x05, 0x00, 0x11, 0x00,
                                  static_cast<uint8_t>(enable ? 0x01 : 0x00)};
    return writeSmartCommand(cmd.data(), cmd.size());
  }
  return true;
}

bool Nikon::writeCurrentTime(const timesync_t &timesync) {
  if (!m_Client || !m_Client->isConnected()) {
    return false;
  }
  const timesync_msg_t msg = {
      .time =
          {
                 .year = static_cast<uint16_t>(timesync.year),
                 .month = static_cast<uint8_t>(timesync.month),
                 .day = static_cast<uint8_t>(timesync.day),
                 .hour = static_cast<uint8_t>(timesync.hour),
                 .minute = static_cast<uint8_t>(timesync.minute),
                 .second = static_cast<uint8_t>(timesync.second),
                 },
      .dst_offset = 0,
      .tz_offset_hours = 0,
      .tz_offset_minutes = 0,
  };
  ESP_LOGI(
      LOG_TAG, "sending TIME = %s",
      NimBLEUtils::dataToHexString(reinterpret_cast<const uint8_t *>(&msg), sizeof(msg)).c_str());
  const bool ok = m_Client->setValue(
      SERVICE_UUID, TIME_CHR_UUID,
      {reinterpret_cast<const uint8_t *>(&msg), static_cast<uint16_t>(sizeof(msg))}, true);
  ESP_LOGI(LOG_TAG, "  TIME %s", ok ? "ok" : "failed");
  return ok;
}

// Rounds a degree value to a fixed number of decimal places and returns
// an integer representation suitable for cheap equality comparison.
// scale = 10^decimal_places, e.g. 10000 for 4 decimal places (~11 m).
inline int32_t degreesToScaledInt(double degrees, int32_t scale) {
  return (int32_t)std::lround(degrees * scale);
}

// ---------------------------------------------------------------------------
// GPS
// ---------------------------------------------------------------------------
void Nikon::updateGeoData(const gps_t &gps, const timesync_t &timesync) {
  // ~11 m threshold (4 decimal places).
  // For ~1.1 m use 100000 instead.
  static constexpr int32_t kScale = 10000;
  int32_t latScaled = degreesToScaledInt(gps.latitude, kScale);
  int32_t lonScaled = degreesToScaledInt(gps.longitude, kScale);
  // Bail out early if position hasn't changed meaningfully
  if (latScaled == m_LatitudeSent && lonScaled == m_LongitudeSent) {
    return;
  }

  if (!m_Client || !m_Client->isConnected()) {
    return;
  }

  // Write current time once before the location information.
  if (isSmartPairingActive()) {
    if (m_SendTimestamp) {
      if (!writeCurrentTime(timesync)) {
        ESP_LOGW(LOG_TAG, "CURRENT_TIME pre-GPS write failed");
      } else {
        m_SendTimestamp = false;
      }
    }
  }

  nikon_time_t ntime = {
      .year = (uint16_t)timesync.year,
      .month = (uint8_t)timesync.month,
      .day = (uint8_t)timesync.day,
      .hour = (uint8_t)timesync.hour,
      .minute = (uint8_t)timesync.minute,
      .second = (uint8_t)timesync.second,
  };

  nikon_geo_t geo = {
      .header = 0x007f,
      .latitude_direction = gps.latitude < 0.0 ? 'S' : 'N',
      .latitude_degrees = 0,
      .latitude_minutes = 0,
      .latitude_submin1 = 0,
      .latitude_submin2 = 0,
      .longitude_direction = gps.longitude < 0.0 ? 'W' : 'E',
      .longitude_degrees = 0,
      .longitude_minutes = 0,
      .longitude_submin1 = 0,
      .longitude_submin2 = 0,
      .satellites = static_cast<uint8_t>(gps.satellites),
      .altitude_ref = gps.altitude < 0.0 ? 'M' : 'P',
      .altitude = (uint16_t)gps.altitude,
      .time = ntime,
      .subseconds = (uint8_t)timesync.centisecond,
      .valid = 0x01,
      .standard = {'W', 'G', 'S', '-', '8', '4'},
      .pad = {0x00},
  };

  degreesToDMSubMin(gps.latitude, geo.latitude_degrees, geo.latitude_minutes, geo.latitude_submin1,
                    geo.latitude_submin2);
  degreesToDMSubMin(gps.longitude, geo.longitude_degrees, geo.longitude_minutes,
                    geo.longitude_submin1, geo.longitude_submin2);

  ESP_LOGI(LOG_TAG, "sending GPS = %s",
           NimBLEUtils::dataToHexString((const uint8_t *)&geo, sizeof(geo)).c_str());
  if (m_Client->setValue(SERVICE_UUID, GEO_CHR_UUID, {(const uint8_t *)&geo, (uint16_t)sizeof(geo)},
                         true)) {
    ESP_LOGI(LOG_TAG, "  success");
    // Only remember the position as "sent" once the write actually succeeds.
    m_LatitudeSent = latScaled;
    m_LongitudeSent = lonScaled;
  } else {
    ESP_LOGI(LOG_TAG, "  failed");
  }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------
bool Nikon::isSmartPairingActive(void) const {
  return (m_Pairing != nullptr && m_Pairing->getType() == Pairing::Type::SMART_DEVICE);
}

bool Nikon::writeSmartCommand(const uint8_t *data, size_t length) {
  if (m_SmartCmdChr == nullptr || data == nullptr || length == 0) {
    return false;
  }
  // Suppress accidental immediate duplicate writes within a 40 ms window.
  const uint32_t nowMs = static_cast<uint32_t>(esp_log_timestamp());
  if (m_LastSmartCmdLen == length && memcmp(m_LastSmartCmd.data(), data, length) == 0
      && (nowMs - m_LastSmartCmdMs) <= 40) {
    ESP_LOGW(LOG_TAG, "suppress duplicate smart cmd = %s",
             NimBLEUtils::dataToHexString(data, length).c_str());
    return true;
  }
  ESP_LOGI(LOG_TAG, "smart cmd = %s", NimBLEUtils::dataToHexString(data, length).c_str());
  const bool ok = m_SmartCmdChr->writeValue(data, length, true);
  if (ok) {
    memcpy(m_LastSmartCmd.data(), data, length);
    m_LastSmartCmdLen = static_cast<uint8_t>(length);
    m_LastSmartCmdMs = nowMs;
  }
  return ok;
}

bool Nikon::sendSmartRemoteControl(uint8_t op, uint8_t group, uint8_t code, uint8_t value) {
  if (!m_Client || !m_Client->isConnected() || m_SmartCmdChr == nullptr) {
    return false;
  }
  // Generic smart command frame: [op 00 group 00 code value]
  std::array<uint8_t, 6> cmd = {op, 0x00, group, 0x00, code, value};
  return writeSmartCommand(cmd.data(), cmd.size());
}

void Nikon::_disconnect(void) {
  m_Client->disconnect();
}

// Converts a decimal-degree value into the Nikon encoding:
// degrees, whole minutes, and two "sub-minute" bytes that
// together represent the fractional minutes as a 4-digit number
// (submin1 = hundredths of a minute, submin2 = hundredths of the
// remainder).
void Nikon::degreesToDMSubMin(double value,
                              uint8_t &degrees,
                              uint8_t &minutes,
                              uint8_t &submin1,
                              uint8_t &submin2) {
  double integral;
  double absValue = std::fabs(value);

  // Whole degrees (truncated, matching Math.floor on a non-negative value).
  std::modf(absValue, &integral);
  degrees = (uint8_t)integral;

  // Remaining fractional degrees, converted to minutes.
  double minutesFull = (absValue - degrees) * 60.0;
  std::modf(minutesFull, &integral);
  minutes = (uint8_t)integral;

  // Remaining fractional minutes, scaled by 100
  double subMinFull = (minutesFull - minutes) * 100.0;
  std::modf(subMinFull, &integral);
  submin1 = (uint8_t)integral;

  // Remaining fractional hundredths-of-a-minute, scaled by 100 again.
  double subMin2Full = (subMinFull - submin1) * 100.0;
  std::modf(subMin2Full, &integral);
  submin2 = (uint8_t)integral;
}

size_t Nikon::getSerialisedBytes(void) const {
  return sizeof(nikon_t);
}

bool Nikon::serialise(void *buffer, size_t bytes) const {
  if (bytes != sizeof(nikon_t)) {
    return false;
  }
  nikon_t *x = static_cast<nikon_t *>(buffer);
  strncpy(x->name, m_Name.c_str(), MAX_NAME);
  x->address = (uint64_t)m_Address;
  x->type = m_Address.getType();
  memcpy(&x->id, &m_ID, sizeof(x->id));

  return true;
}

}  // namespace Furble
