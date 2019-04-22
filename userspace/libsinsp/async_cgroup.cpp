#include "async_cgroup.h"

#include <fstream>
#include "sinsp.h"

namespace {
// to prevent 32-bit number of kilobytes from overflowing, ignore values larger than 4 TiB.
// This reports extremely large values (e.g. almost-but-not-quite 9EiB as set by k8s) as unlimited.
// Note: we use the same maximum value for cpu shares/quotas as well; the typical values are much lower
// and so should never exceed CGROUP_VAL_MAX either
constexpr const int64_t CGROUP_VAL_MAX = 1L << 42;

bool read_cgroup_val(std::shared_ptr<std::string>& subsys, const std::string& cgroup, const std::string& filename, int64_t& out)
{
	if(cgroup == "/")
	{
		return false;
	}

	std::string path = *subsys.get() + "/" + cgroup + "/" + filename;
	std::ifstream cg_val(path);

	int64_t val;
	cg_val >> val;

	if(val > 0 && val < CGROUP_VAL_MAX)
	{
		out = val;
		return true;
	}
	return false;
}
}

namespace libsinsp {
namespace async_cgroup {

bool get_cgroup_resource_limits(const delayed_cgroup_key& key, delayed_cgroup_value& value)
{
	bool found_all;

	std::shared_ptr<std::string> memcg_root = sinsp::lookup_cgroup_dir("memory");
	found_all = read_cgroup_val(memcg_root, key.m_mem_cgroup, "memory.limit_in_bytes", value.m_memory_limit);

	std::shared_ptr<std::string> cpucg_root = sinsp::lookup_cgroup_dir("cpu");
	found_all = read_cgroup_val(cpucg_root, key.m_cpu_cgroup, "cpu.shares", value.m_cpu_shares) && found_all;
	found_all = read_cgroup_val(cpucg_root, key.m_cpu_cgroup, "cpu.cfs_quota_us", value.m_cpu_quota) && found_all;
	found_all = read_cgroup_val(cpucg_root, key.m_cpu_cgroup, "cpu.cfs_period_us", value.m_cpu_period) && found_all;

	return found_all;
}

void delayed_cgroup_lookup::run_impl()
{
	delayed_cgroup_key key;
	while(dequeue_next_key(key)) {
		delayed_cgroup_value value;
		get_cgroup_resource_limits(key, value);
		store_value(key, value);
	}
}

void delayed_cgroup_lookup::tick(sinsp_container_manager* manager)
{
	auto cgroup_data = get_complete_results();

	for(const auto& it : cgroup_data)
	{
		auto container = manager->get_container(it.first.m_container_id);
		if(container)
		{
			container->m_memory_limit = it.second.m_memory_limit;
			container->m_cpu_shares = it.second.m_cpu_shares;
			container->m_cpu_quota = it.second.m_cpu_quota;
			container->m_cpu_period = it.second.m_cpu_period;
		}
	}
}
}
}
