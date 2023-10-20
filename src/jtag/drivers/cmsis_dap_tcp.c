// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Copyright (C) 2018 by Mickaël Thomas                                  *
 *   mickael9@gmail.com                                                    *
 *                                                                         *
 *   Copyright (C) 2016 by Maksym Hilliaka                                 *
 *   oter@frozen-team.com                                                  *
 *                                                                         *
 *   Copyright (C) 2016 by Phillip Pearson                                 *
 *   pp@myelin.co.nz                                                       *
 *                                                                         *
 *   Copyright (C) 2014 by Paul Fertser                                    *
 *   fercerpav@gmail.com                                                   *
 *                                                                         *
 *   Copyright (C) 2013 by mike brown                                      *
 *   mike@theshedworks.org.uk                                              *
 *                                                                         *
 *   Copyright (C) 2013 by Spencer Oliver                                  *
 *   spen@spen-soft.co.uk                                                  *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "cmsis_dap.h"
#include <arpa/inet.h>
#include <helper/log.h>
#include <helper/replacements.h>
#include <helper/system.h>
#include <string.h>
#include <sys/socket.h>

struct cmsis_dap_backend_data {
  int sk_fd;
};

#define EL_LINK_IDENTIFIER 0x8a656c70
#define EL_DAP_VERSION 0x00000001
#define EL_COMMAND_HANDSHAKE 0x00000000

#define EL_TIMEOUT 500000

typedef struct {
  uint32_t el_link_identifier;
  uint32_t command;
  uint32_t el_proxy_version;
} __attribute__((packed)) el_request_handshake;

struct sockaddr_in device_addr;

static void cmsis_dap_tcp_close(struct cmsis_dap *dap);
static int cmsis_dap_tcp_alloc(struct cmsis_dap *dap, unsigned int pkt_sz);

static int cmsis_dap_tcp_open(struct cmsis_dap *dap, uint16_t vids[],
                              uint16_t pids[], const char *serial) {
  int err;
  int sk_fd = 0;

  sk_fd = socket(AF_INET, SOCK_STREAM, 0);

  if (sk_fd < 0) {
    LOG_ERROR("\n Socket creation error \n");
    return ERROR_FAIL;
  }

  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = EL_TIMEOUT;
  setsockopt(sk_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

  err = connect(sk_fd, (struct sockaddr *)&device_addr, sizeof(device_addr));
  if (err < 0) {
    LOG_ERROR("Connection Failed \n");
    return ERROR_FAIL;
  }

  // handeshake

  el_request_handshake handleshake;
  handleshake.command = htonl(EL_COMMAND_HANDSHAKE);
  handleshake.el_link_identifier = htonl(EL_LINK_IDENTIFIER);
  handleshake.el_proxy_version = htonl(EL_DAP_VERSION);

  err = send(sk_fd, &handleshake, sizeof(el_request_handshake), 0);
  if (err < 0) {
    LOG_ERROR("handleshake send Failed \n");
    return ERROR_FAIL;
  }

  err = read(sk_fd, &handleshake, sizeof(el_request_handshake));
  if (err < 0) {
    LOG_ERROR("handleshake read Failed \n");
    return ERROR_FAIL;
  }

  if (err != sizeof(el_request_handshake)) {
    // TODO check
    LOG_ERROR("handleshake check Failed \n");
    return ERROR_FAIL;
  }

  dap->bdata = malloc(sizeof(struct cmsis_dap_backend_data));
  if (!dap->bdata) {
    LOG_ERROR("unable to allocate memory");
    close(sk_fd);
    return ERROR_FAIL;
  }

  LOG_INFO("handleshake success");

  dap->bdata->sk_fd = sk_fd;

  unsigned int packet_size = 64;

  int retval = cmsis_dap_tcp_alloc(dap, packet_size);
  if (retval != ERROR_OK) {
    cmsis_dap_tcp_close(dap);
    return ERROR_FAIL;
  }
  return ERROR_OK;
}

static void cmsis_dap_tcp_close(struct cmsis_dap *dap) {

  close(dap->bdata->sk_fd);
  free(dap->bdata);
  dap->bdata = NULL;
  free(dap->packet_buffer);
  dap->packet_buffer = NULL;
}

static int cmsis_dap_tcp_read(struct cmsis_dap *dap, int timeout_ms) {
  int transferred = 0;
  transferred = read(dap->bdata->sk_fd, dap->packet_buffer, dap->packet_size);
  if (transferred < 0) {
    if (errno == EAGAIN) {
      LOG_ERROR("timeout reading data: ");
      return ERROR_TIMEOUT_REACHED;
    } else {
      LOG_ERROR("error reading data: ");
      return ERROR_FAIL;
    }
  }

  memset(&dap->packet_buffer[transferred], 0,
         dap->packet_buffer_size - transferred);

  return transferred;
}

static int cmsis_dap_tcp_write(struct cmsis_dap *dap, int txlen,
                               int timeout_ms) {
  int transferred = 0;

  transferred = send(dap->bdata->sk_fd, dap->packet_buffer, txlen, 0);
  if (transferred < 0) {
    if (errno == EAGAIN) {
      LOG_ERROR("timeout sending data: ");
      return ERROR_TIMEOUT_REACHED;
    } else {
      LOG_ERROR("error sending data: ");
      return ERROR_FAIL;
    }
  }
  return transferred;
}

static int cmsis_dap_tcp_alloc(struct cmsis_dap *dap, unsigned int pkt_sz) {
  uint8_t *buf = malloc(pkt_sz);
  if (!buf) {
    LOG_ERROR("unable to allocate CMSIS-DAP packet buffer");
    return ERROR_FAIL;
  }

  dap->packet_buffer = buf;
  dap->packet_size = pkt_sz;
  dap->packet_buffer_size = pkt_sz;
  /* Prevent sending zero size USB packets */
  dap->packet_usable_size = pkt_sz - 1;

  dap->command = dap->packet_buffer;
  dap->response = dap->packet_buffer;

  return ERROR_OK;
}

COMMAND_HANDLER(cmsis_dap_tcp_interface_command) {
  if (CMD_ARGC == 1) {
    device_addr.sin_family = AF_INET;
    device_addr.sin_port = htons(3240);
    char *pos = strchr(CMD_ARGV[0], ':');
    if (pos) {
      //TODO ...
    } else {
      if (inet_pton(AF_INET, CMD_ARGV[0], &device_addr.sin_addr) <= 0) {
        LOG_ERROR("device addr parse failed");
        return ERROR_FAIL;
      }
    }
  } else
    LOG_ERROR("expected exactly one argument to cmsis_dap_tcp_interface "
              "<interface_number>");

  return ERROR_OK;
}

const struct command_registration cmsis_dap_tcp_subcommand_handlers[] = {
    {
        .name = "host",
        .handler = &cmsis_dap_tcp_interface_command,
        .mode = COMMAND_CONFIG,
        .help = "set the USB host/ip address (for USB TCP backend only)",
        .usage = "<ip:port>",
    },
    COMMAND_REGISTRATION_DONE};

const struct cmsis_dap_backend cmsis_dap_tcp_backend = {
    .name = "tcp",
    .open = cmsis_dap_tcp_open,
    .close = cmsis_dap_tcp_close,
    .read = cmsis_dap_tcp_read,
    .write = cmsis_dap_tcp_write,
    .packet_buffer_alloc = cmsis_dap_tcp_alloc,
};
