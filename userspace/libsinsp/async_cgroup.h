#pragma once

#include <string>
#include "async_key_value_source.h"

class sinsp_container_manager;

namespace libsinsp {
namespace async_cgroup {

struct delayed_cgroup_key {
	delayed_cgroup_key():
		m_container_id(""),
		m_cpu_cgroup(""),
		m_mem_cgroup("") {}

	delayed_cgroup_key(const std::string& container_id, const std::string& cpu_cgroup_dir, const std::string& mem_cgroup_dir):
		m_container_id(container_id),
		m_cpu_cgroup(cpu_cgroup_dir),
		m_mem_cgroup(mem_cgroup_dir) {}

	bool operator<(const delayed_cgroup_key& rhs) const
	{
		return m_container_id < rhs.m_container_id &&
			m_cpu_cgroup < rhs.m_cpu_cgroup &&
			m_mem_cgroup < rhs.m_mem_cgroup;
	}

	bool operator==(const delayed_cgroup_key& rhs) const
	{
		return m_container_id == rhs.m_container_id &&
			m_cpu_cgroup == rhs.m_cpu_cgroup &&
			m_mem_cgroup == rhs.m_mem_cgroup;
	}

	std::string m_container_id; // TODO a shared_ptr would be nice
	std::string m_cpu_cgroup;
	std::string m_mem_cgroup;
};

struct delayed_cgroup_value {
	delayed_cgroup_value():
		m_cpu_shares(0),
		m_cpu_quota(0),
		m_cpu_period(0),
		m_memory_limit(0) {}

	delayed_cgroup_value(int64_t cpu_shares, int64_t, int64_t cpu_quota, int64_t cpu_period, int64_t memory_limit):
		m_cpu_shares(cpu_shares),
		m_cpu_quota(cpu_quota),
		m_cpu_period(cpu_period),
		m_memory_limit(memory_limit) {}

	int64_t m_cpu_shares;
	int64_t m_cpu_quota;
	int64_t m_cpu_period;
	int64_t m_memory_limit;
};

bool get_cgroup_resource_limits(const delayed_cgroup_key& key, delayed_cgroup_value& value);

class delayed_cgroup_lookup : public sysdig::async_key_value_source<delayed_cgroup_key, delayed_cgroup_value> {
public:
	using sysdig::async_key_value_source<delayed_cgroup_key, delayed_cgroup_value>::async_key_value_source;

	void tick(sinsp_container_manager* manager);
private:
	void run_impl() override;
};
}
}

namespace std {
template<> struct hash<libsinsp::async_cgroup::delayed_cgroup_key> {
	std::size_t operator()(const libsinsp::async_cgroup::delayed_cgroup_key& h) const {
		size_t h1 = ::std::hash<std::string>{}(h.m_container_id);
		size_t h2 = ::std::hash<std::string>{}(h.m_cpu_cgroup);
		size_t h3 = ::std::hash<std::string>{}(h.m_mem_cgroup);
		return h1 ^ (h2 << 1u) ^ (h3 << 2u);
	}
};
}
