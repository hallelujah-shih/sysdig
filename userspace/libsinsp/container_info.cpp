/*
Copyright (C) 2013-2018 Draios Inc dba Sysdig.

This file is part of sysdig.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#include "container_info.h"
#include "container_engine/docker.h"
#include "sinsp.h"
#include "sinsp_int.h"

const sinsp_container_info::container_mount_info *sinsp_container_info::mount_by_idx(uint32_t idx) const
{
	if (idx >= m_mounts.size())
	{
		return NULL;
	}

	return &(m_mounts[idx]);
}

const sinsp_container_info::container_mount_info *sinsp_container_info::mount_by_source(std::string &source) const
{
	// note: linear search
	for (auto &mntinfo :m_mounts)
	{
		if(sinsp_utils::glob_match(source.c_str(), mntinfo.m_source.c_str()))
		{
			return &mntinfo;
		}
	}

	return NULL;
}

const sinsp_container_info::container_mount_info *sinsp_container_info::mount_by_dest(std::string &dest) const
{
	// note: linear search
	for (auto &mntinfo :m_mounts)
	{
		if(sinsp_utils::glob_match(dest.c_str(), mntinfo.m_dest.c_str()))
		{
			return &mntinfo;
		}
	}

	return NULL;
}

std::string sinsp_container_info::normalize_healthcheck_arg(const std::string &arg)
{
	std::string ret = arg;

	if(ret.empty())
	{
		return ret;
	}

	// Remove pairs of leading/trailing " or ' chars, if present
	while(ret.front() == '"' || ret.front() == '\'')
	{
		if(ret.back() == ret.front())
		{
			ret.pop_back();
			ret.erase(0, 1);
		}
	}

	return ret;
}

void sinsp_container_info::parse_healthcheck(const Json::Value &healthcheck_obj)
{
	if(!healthcheck_obj.isNull())
	{
		const Json::Value &test_obj = healthcheck_obj["Test"];

		if(!test_obj.isNull() && test_obj.isArray() && test_obj.size() >= 2)
		{
			if(test_obj[0].asString() == "CMD")
			{
				m_has_healthcheck = true;
				m_healthcheck_exe = normalize_healthcheck_arg(test_obj[1].asString());

				for(uint32_t i = 2; i < test_obj.size(); i++)
				{
					m_healthcheck_args.push_back(normalize_healthcheck_arg(test_obj[i].asString()));
				}
			}
			else if(test_obj[0].asString() == "CMD-SHELL")
			{
				m_has_healthcheck = true;
				m_healthcheck_exe = "/bin/sh";
				m_healthcheck_args.push_back("-c");
				m_healthcheck_args.push_back(test_obj[1].asString());
			}
		}
	}
}

namespace {
const Json::Value parse_container_json_event(sinsp_evt* evt, std::string& out_json)
{
	ASSERT(evt->get_type() == PPME_CONTAINER_JSON_E);
	sinsp_evt_param *parinfo = evt->get_param(0);
	ASSERT(parinfo);
	ASSERT(parinfo->m_len > 0);
	std::string json(parinfo->m_val, parinfo->m_len);
	g_logger.format(sinsp_logger::SEV_DEBUG, "Parsing Container JSON=%s", json.c_str());
	Json::Value root;
	if(!Json::Reader().parse(json, root))
	{
		std::string errstr;
		errstr = Json::Reader().getFormattedErrorMessages();
		throw sinsp_exception("Invalid JSON encountered while parsing container info: " + json + "error=" + errstr);
	}
	const Json::Value& container = root["container"];

	out_json = std::move(json);

	return container;
}
}

sinsp_container_info sinsp_container_info::from_container_json(sinsp_evt *evt)
{
	std::string json;
	const auto container = parse_container_json_event(evt, json);

	sinsp_container_info container_info;
	const Json::Value& id = container["id"];
	if(!id.isNull() && id.isConvertibleTo(Json::stringValue))
	{
		container_info.m_id = id.asString();
	}
	const Json::Value& type = container["type"];
	if(!type.isNull() && type.isConvertibleTo(Json::uintValue))
	{
		container_info.m_type = static_cast<sinsp_container_type>(type.asUInt());
	}
	const Json::Value& name = container["name"];
	if(!name.isNull() && name.isConvertibleTo(Json::stringValue))
	{
		container_info.m_name = name.asString();
	}

	const Json::Value& is_pod_sandbox = container["isPodSandbox"];
	if(!is_pod_sandbox.isNull() && is_pod_sandbox.isConvertibleTo(Json::booleanValue))
	{
		container_info.m_is_pod_sandbox = is_pod_sandbox.asBool();
	}

	const Json::Value& image = container["image"];
	if(!image.isNull() && image.isConvertibleTo(Json::stringValue))
	{
		container_info.m_image = image.asString();
	}
	const Json::Value& imageid = container["imageid"];
	if(!imageid.isNull() && imageid.isConvertibleTo(Json::stringValue))
	{
		container_info.m_imageid = imageid.asString();
	}
	const Json::Value& imagerepo = container["imagerepo"];
	if(!imagerepo.isNull() && imagerepo.isConvertibleTo(Json::stringValue))
	{
		container_info.m_imagerepo = imagerepo.asString();
	}
	const Json::Value& imagetag = container["imagetag"];
	if(!imagetag.isNull() && imagetag.isConvertibleTo(Json::stringValue))
	{
		container_info.m_imagetag = imagetag.asString();
	}
	const Json::Value& imagedigest = container["imagedigest"];
	if(!imagedigest.isNull() && imagedigest.isConvertibleTo(Json::stringValue))
	{
		container_info.m_imagedigest = imagedigest.asString();
	}
	const Json::Value& privileged = container["privileged"];
	if(!privileged.isNull() && privileged.isConvertibleTo(Json::booleanValue))
	{
		container_info.m_privileged = privileged.asBool();
	}

	libsinsp::container_engine::docker::parse_json_mounts(container["Mounts"], container_info.m_mounts);

	container_info.parse_healthcheck(container["Healthcheck"]);
	const Json::Value& contip = container["ip"];
	if(!contip.isNull() && contip.isConvertibleTo(Json::stringValue))
	{
		uint32_t ip;

		if(inet_pton(AF_INET, contip.asString().c_str(), &ip) == -1)
		{
			throw sinsp_exception("Invalid 'ip' field while parsing container info: " + json);
		}

		container_info.m_container_ip = ntohl(ip);
	}

	const Json::Value &port_mappings = container["port_mappings"];

	if(!port_mappings.isNull() && port_mappings.isConvertibleTo(Json::arrayValue))
	{
		for (Json::Value::ArrayIndex i = 0; i != port_mappings.size(); i++)
		{
			sinsp_container_info::container_port_mapping map;
			map.m_host_ip = port_mappings[i]["HostIp"].asInt();
			map.m_host_port = (uint16_t) port_mappings[i]["HostPort"].asInt();
			map.m_container_port = (uint16_t) port_mappings[i]["ContainerPort"].asInt();

			container_info.m_port_mappings.push_back(map);
		}
	}

	vector<string> labels = container["labels"].getMemberNames();
	for(vector<string>::const_iterator it = labels.begin(); it != labels.end(); ++it)
	{
		string val = container["labels"][*it].asString();
		container_info.m_labels[*it] = val;
	}

	const Json::Value& env_vars = container["env"];

	for(const auto& env_var : env_vars)
	{
		if(env_var.isString())
		{
			container_info.m_env.emplace_back(env_var.asString());
		}
	}

	const Json::Value& memory_limit = container["memory_limit"];
	if(!memory_limit.isNull() && memory_limit.isConvertibleTo(Json::uintValue))
	{
		container_info.m_memory_limit = memory_limit.asUInt();
	}

	const Json::Value& swap_limit = container["swap_limit"];
	if(!swap_limit.isNull() && swap_limit.isConvertibleTo(Json::uintValue))
	{
		container_info.m_swap_limit = swap_limit.asUInt();
	}

	const Json::Value& cpu_shares = container["cpu_shares"];
	if(!cpu_shares.isNull() && cpu_shares.isConvertibleTo(Json::uintValue))
	{
		container_info.m_cpu_shares = cpu_shares.asUInt();
	}

	const Json::Value& cpu_quota = container["cpu_quota"];
	if(!cpu_quota.isNull() && cpu_quota.isConvertibleTo(Json::uintValue))
	{
		container_info.m_cpu_quota = cpu_quota.asUInt();
	}

	const Json::Value& cpu_period = container["cpu_period"];
	if(!cpu_period.isNull() && cpu_period.isConvertibleTo(Json::uintValue))
	{
		container_info.m_cpu_period = cpu_period.asUInt();
	}

	const Json::Value& mesos_task_id = container["mesos_task_id"];
	if(!mesos_task_id.isNull() && mesos_task_id.isConvertibleTo(Json::stringValue))
	{
		container_info.m_mesos_task_id = mesos_task_id.asString();
	}

	const Json::Value& metadata_deadline = container["metadata_deadline"];
	// isConvertibleTo doesn't seem to work on large 64 bit numbers
	if(!metadata_deadline.isNull() && metadata_deadline.isUInt64())
	{
		container_info.m_metadata_deadline = metadata_deadline.asUInt64();
	}

	return container_info;
}

std::string sinsp_container_info::get_id_from_json(sinsp_evt *evt)
{
	std::string json;
	const auto container = parse_container_json_event(evt, json);

	const Json::Value& id = container["id"];
	if(id.isNull() || !id.isConvertibleTo(Json::stringValue))
	{
		throw sinsp_exception("Invalid or missing container id in JSON: " + json);
	}
	return id.asString();
}