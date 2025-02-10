import clibfabric as fab
import ctypes, time, logging, errno, os

class TryAgainError(OSError):
	"""Exception raised when a function returns -EAGAIN."""
	def __init__(self):
		super().__init__(errno.EAGAIN, "Resource temporarily unavailable, try again.")


class Version:
	def __init__(self, major, minor):
		self.__version = (((major) << 16) | (minor))

	def get_version(self):
		return self.__version

# {'caps': <>, 'mode': <>, fabric: {'name': <>, api_version: <>}}
class Info:
	def __init__(self, dinfo=None):
		self.__fi_info = fab.fi_info()
		self.__dom_attr = fab.fi_domain_attr()
		self.__fab_attr = fab.fi_fabric_attr()
		self.__rx_attr = fab.fi_rx_attr()
		self.__tx_attr = fab.fi_tx_attr()
		self.__ep_attr = fab.fi_ep_attr()
		# connect
		self.__fi_info.fi_fabric_attr = self.__fab_attr
		self.__fi_info.fi_domain_attr = self.__dom_attr
		self.__fi_info.fi_rx_attr = self.__rx_attr
		self.__fi_info.fi_tx_attr = self.__tx_attr
		self.__fi_info.fi_ep_attr = self.__ep_attr

		# initialize the fi_info properly so it's visible to C code
		fab.fi_info_init(self.__fi_info, self.__fab_attr,
				self.__dom_attr, self.__rx_attr,
				self.__tx_attr, self.__ep_attr)

		if dinfo:
			self.dict2info(dinfo)

	def dict2info(self, dinfo):
		try:
			self.set_caps(dinfo['caps'])
		except:
			pass
		try:
			self.set_mode(dinfo['mode'])
		except:
			pass
		try:
			self.set_addr_format(dinfo['addr-format'])
		except:
			pass
		try:
			self.set_fab_attr_prov_name(dinfo['fab-attr']['prov-name'])
		except:
			pass
		try:
			self.set_dom_attr_mr_mode(dinfo['dom-attr']['mr-mode'])
		except:
			pass
		try:
			self.set_dom_attr_threading(dinfo['dom-attr']['threading'])
		except:
			pass
		try:
			self.set_dom_attr_cq_data_size(dinfo['dom-attr']['cq-data-size'])
		except:
			pass
		try:
			self.set_dom_attr_control_progress(dinfo['dom-attr']['control-progress'])
		except:
			pass
		try:
			self.set_dom_attr_data_progress(dinfo['dom-attr']['data-progress'])
		except:
			pass
		try:
			self.set_dom_attr_av_type(dinfo['dom-attr']['av-type'])
		except:
			pass
		try:
			self.set_dom_attr_resource_mgmt(dinfo['dom-attr']['resource-mgmt'])
		except:
			pass
		try:
			self.set_rx_attr_msg_order(dinfo['rx-attr']['msg-order'])
		except:
			pass
		try:
			self.set_rx_attr_op_flags(dinfo['rx-attr']['op-flags'])
		except:
			pass
		try:
			self.set_tx_attr_msg_order(dinfo['tx-attr']['msg-order'])
		except:
			pass
		try:
			self.set_tx_attr_op_flags(dinfo['tx-attr']['op-flags'])
		except:
			pass

	def free(self):
		fab.fi_freeinfo(self.__fi_info)

	def generate(self):
		return fab.fi_dupinfo(self.__fi_info)

	def set_caps(self, caps):
		self.__fi_info.caps = caps

	def set_mode(self, mode):
		self.__fi_info.mode = mode

	def set_addr_format(self, addr_format):
		self.__fi_info.addr_format = addr_format

	def set_fab_attr_prov_name(self, prov_name):
		self.__fi_info.fab_attr.prov_name = prov_name

	def set_dom_attr_mr_mode(self, mr_mode):
		self.__dom_attr.mr_mode = mr_mode

	def set_dom_attr_threading(self, threading):
		self.__dom_attr.threading = threading

	def set_dom_attr_cq_data_size(self, size):
		self.__dom_attr.cq_data_size = size

	def set_dom_attr_control_progress(self, progress):
		self.__dom_attr.control_progress = progress

	def set_dom_attr_data_progress(self, progress):
		self.__dom_attr.data_progress = progress

	def set_dom_attr_av_type(self, avtype):
		self.__dom_attr.av_type = avtype

	def set_dom_attr_resource_mgmt(self, mgmt):
		self.__dom_attr.resource_mgmt = mgmt

	def set_ep_attr_type(self, eptype):
		self.__ep_attr.type = eptype

	def set_rx_attr_msg_order(self, order):
		self.__rx_attr.msg_order = order

	def set_rx_attr_op_flags(self, flags):
		self.__rx_attr.op_flags = flags

	def set_tx_attr_msg_order(self, order):
		self.__tx_attr.msg_order = order

	def set_tx_attr_op_flags(self, flags):
		self.__tx_attr.op_flags = flags

class Endpoint:
	def __init__(self, domain, info):
		self.__domain = domain
		rc, self.__ep = fab.fi_endpoint(domain, info, None)
		if (rc):
			raise ValueError(f"Failed to create ep on domain {info.domain_attr.name}")

	def bind_cq(self, cq, flags=fab.FI_TRANSMIT|fab.FI_RECV):
		rc = fab.fi_ep_bind(self.__ep, cq.fid(), flags)
		if rc:
			raise ValueError(f"Failed to bind cq to endpoint: {rc}")

	def bind_av(self, av, flags=0):
		rc = fab.fi_ep_bind(self.__ep, av.fid(), flags)
		if rc:
			raise ValueError(f"Failed to bind av to endpoint: {rc}")

	def fid(self):
		return fab.get_ep_fid(self.__ep)

	def enable(self):
		rc = fab.fi_enable(self.__ep)
		if rc:
			raise ValueError("Failed to enable endpoint")

	def get_name(self):
		buf = bytearray(1)
		rc, data, size = fab.fi_getname(self.fid(), buf)
		if rc and rc != -fab.FI_ETOOSMALL:
			raise ValueError(f"Failed to get ep name: {rc}")
		buf = bytearray(size)
		rc, data, size = fab.fi_getname(self.fid(), buf)
		if rc:
			raise ValueError(f"Failed to get ep name: {rc}")
		return data

	def post_trecv(self, buf, src_addr, tag, ignore, context, desc=None):
		rc = fab.fi_trecv(self.__ep, buf, desc, src_addr, tag, ignore, context)
		if rc:
			raise ValueError(f"trecv failed: {rc}")

	def tsenddata(self, buf, dest_addr, tag, context, desc=None, data=0):
		rc = fab.fi_tsenddata(self.__ep, buf, desc, data, dest_addr, tag, context)
		if rc == -fab.FI_EAGAIN:
			raise TryAgainError()
		if rc:
			raise ValueError(f"tsenddata failed: {rc}")

	def close(self):
		rc = fab.fi_close(self.fid())
		if rc:
			raise ValueError("Failed to close AV")

class CompletionQueue:
	def __init__(self, domain, info, size, cqformat, flags):
		self.__domain = domain
		self.__info = info

		cq_attr = fab.fi_cq_attr()
		cq_attr.size = size
		cq_attr.format = cqformat
		cq_attr.flags = flags

		rc, self.__cq = fab.fi_cq_open(self.__domain, cq_attr, None)
		if (rc):
			raise ValueError("Failed to create AV")

	def fid(self):
		return fab.get_cq_fid(self.__cq)

	def read(self, count=100):
		buf = bytearray(fab.sizeof_fi_cq_tagged_entry() * count)
		rc, events = fab.fi_cq_read(self.__cq, buf)
		if rc > 0:
			return rc, events
		if rc <= 0 and rc != -fab.FI_EAGAIN:
			raise ValueError(f"Operation Failure: {rc}")
		elif rc == -fab.FI_EAGAIN:
			raise TryAgainError()

	def close(self):
		rc = fab.fi_close(self.fid())
		if rc:
			raise ValueError("Failed to close AV")

class AddressVectorTable:
	def __init__(self, domain, avtype, count):
		self.__domain = domain

		av_attr = fab.fi_av_attr()
		av_attr.type = avtype
		av_attr.count = count

		rc, self.__av = fab.fi_av_open(self.__domain, av_attr, None)
		if (rc):
			raise ValueError(f"Failed to create av on domain {rc}")

	def insert_addr(self, addr, count=1, flags=0):
		if fab.FI_AV_USER_ID & flags:
			raise ValueError("Can not set FI_AV_USER_ID in flags parameter")
		rc, fi_addr = fab.fi_av_insert(self.__av, addr,
								 list(range(count)), flags, None)
		if rc <= 0:
			raise ValueError(f"Failed to insert address in av: {rc}")
		return fi_addr

	def fid(self):
		return fab.get_av_fid(self.__av)

	def close(self):
		rc = fab.fi_close(self.fid())
		if rc:
			raise ValueError(f"Failed to close AV: {rc}")

class Domain:
	def __init__(self, fabric, info):
		self.__eps = []
		self.__cqs = []
		self.__avs = []

		self.__info = info
		rc, self.__domain = fab.fi_domain(fabric, info, None)
		if rc:
			raise ValueError(f"Failed to create domain {info.domain_attr.name}: {rc}")

	def add_ep(self):
		ep = Endpoint(self.__domain, self.__info)
		self.__eps.append(ep)
		return ep

	def add_cq(self, size=1024, cq_format=fab.FI_CQ_FORMAT_TAGGED, flags=0):
		cq = CompletionQueue(self.__domain, self.__info, size, cq_format, flags)
		self.__cqs.append(cq)
		return cq

	def add_av(self, avtype=fab.FI_AV_TABLE, count=256):
		av = AddressVectorTable(self.__domain, avtype, count)
		self.__avs.append(av)
		return av

	def fid(self):
		return fab.get_dom_fid(self.__domain)

	def close(self):
		for ep in self.__eps:
			ep.close()
		for av in self.__avs:
			av.close()
		for cq in self.__cqs:
			cq.close()
		rc = fab.fi_close(self.fid())
		if rc:
			raise ValueError("Failed to close AV")

class Fabric:
	dinfo = {'caps': fab.FI_HMEM | fab.FI_MSG | fab.FI_TAGGED | fab.FI_LOCAL_COMM | fab.FI_DIRECTED_RECV,
     'dom-attr': {'mr-mode': fab.FI_MR_VIRT_ADDR | fab.FI_MR_HMEM | fab.FI_MR_PROV_KEY,
				  'threading': fab.FI_THREAD_DOMAIN},
	 'tx_attr': {'msg_order': fab.FI_ORDER_SAS, 'op-flags': fab.FI_COMPLETION},
	 'rx_attr': {'msg_order': fab.FI_ORDER_SAS, 'op-flags': fab.FI_COMPLETION}}

	def __init__(self, hints=None, version=None):
		self.__domains = []
		self.__fabric = None

		if not version:
			version = Version(1, 21)

		if not hints:
			fi = Info(dinfo=Fabric.dinfo)
			self.__fi_hints = fi.generate()
		elif type(hints) == dict:
			fi = Info(dinfo=hints)
			self.__fi_hints = fi.generate()
		else:
			raise TypeError("hints is not a dictionary")

		rc, self.__fi_infos = fab.fi_getinfo(version.get_version(),
							None, None, 0, self.__fi_hints)
		if rc:
			raise ValueError(f"fi_getinfo failed: {rc}")

	class ReqContext:
		def __init__(self, pid, req_id):
			self.__context = fab.fi_req_context()
			self.__context.pid = pid
			self.__context.req_id = req_id

		def get_context(self):
			return self.__context;

	def get_op_context(self, op_context):
		return fab.get_req_context(op_context)

	def info2dict(self):
		fi = self.__fi_infos
		dinfo = {}
		while fi:
			if fi.fabric_attr.prov_name in dinfo:
				dinfo[fi.fabric_attr.prov_name].append(fi.domain_attr.name)
			else:
				dinfo[fi.fabric_attr.prov_name] = [fi.domain_attr.name]
			fi = fi.next
		return dinfo

	def add_domain(self, domain_name):
		fi = self.__fi_infos
		all_doms = []
		dom = None
		while fi:
			if fi.domain_attr.name == domain_name:
				if not self.__fabric:
					rc, self.__fabric = fab.fi_fabric(fi.fabric_attr, None)
					if rc:
						raise ValueError(f"Failed to create fabric: {fi.fabric_attr.prov_name}")
				dom = Domain(self.__fabric, fi)
				break
			all_doms.append(fi.domain_attr.name)
			fi = fi.next
		if not dom:
			raise ValueError(f"domain {domain_name} not found. Available: {all_doms}")

		self.__domains.append(dom)

		return dom

	def fid(self):
		return fab.get_fab_fid(self.__fabric)

	def close(self):
		for dom in self.__domains:
			dom.close()
		rc = fab.fi_close(self.fid())
		if rc:
			raise ValueError(f"Failed to close fabric: {rc}")

