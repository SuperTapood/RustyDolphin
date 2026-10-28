#pragma once

#include <memory>
#include <pcap.h>

struct PcapCloser {
	void operator()(pcap_t* handle) const noexcept { if (handle) pcap_close(handle); }
};

using PcapHandle = std::unique_ptr<pcap_t, PcapCloser>;
