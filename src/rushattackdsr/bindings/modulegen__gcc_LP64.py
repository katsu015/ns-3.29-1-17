from pybindgen import Module, FileCodeSink, param, retval, cppclass, typehandlers


import pybindgen.settings
import warnings

class ErrorHandler(pybindgen.settings.ErrorHandler):
    def handle_error(self, wrapper, exception, traceback_):
        warnings.warn("exception %r in wrapper %s" % (exception, wrapper))
        return True
pybindgen.settings.error_handler = ErrorHandler()


import sys

def module_init():
    root_module = Module('ns.rushattackdsr', cpp_namespace='::ns3')
    return root_module

def register_types(module):
    root_module = module.get_root()
    
    ## qos-utils.h (module 'wifi'): ns3::AcIndex [enumeration]
    module.add_enum('AcIndex', ['AC_BE', 'AC_BK', 'AC_VI', 'AC_VO', 'AC_BE_NQOS', 'AC_UNDEF'], import_from_module='ns.wifi')
    ## wifi-preamble.h (module 'wifi'): ns3::WifiPreamble [enumeration]
    module.add_enum('WifiPreamble', ['WIFI_PREAMBLE_LONG', 'WIFI_PREAMBLE_SHORT', 'WIFI_PREAMBLE_HT_MF', 'WIFI_PREAMBLE_HT_GF', 'WIFI_PREAMBLE_VHT', 'WIFI_PREAMBLE_HE_SU', 'WIFI_PREAMBLE_HE_ER_SU', 'WIFI_PREAMBLE_HE_MU', 'WIFI_PREAMBLE_HE_TB', 'WIFI_PREAMBLE_NONE'], import_from_module='ns.wifi')
    ## wifi-mode.h (module 'wifi'): ns3::WifiModulationClass [enumeration]
    module.add_enum('WifiModulationClass', ['WIFI_MOD_CLASS_UNKNOWN', 'WIFI_MOD_CLASS_IR', 'WIFI_MOD_CLASS_FHSS', 'WIFI_MOD_CLASS_DSSS', 'WIFI_MOD_CLASS_HR_DSSS', 'WIFI_MOD_CLASS_ERP_PBCC', 'WIFI_MOD_CLASS_DSSS_OFDM', 'WIFI_MOD_CLASS_ERP_OFDM', 'WIFI_MOD_CLASS_OFDM', 'WIFI_MOD_CLASS_HT', 'WIFI_MOD_CLASS_VHT', 'WIFI_MOD_CLASS_HE'], import_from_module='ns.wifi')
    ## wifi-mode.h (module 'wifi'): ns3::WifiCodeRate [enumeration]
    module.add_enum('WifiCodeRate', ['WIFI_CODE_RATE_UNDEFINED', 'WIFI_CODE_RATE_3_4', 'WIFI_CODE_RATE_2_3', 'WIFI_CODE_RATE_1_2', 'WIFI_CODE_RATE_5_6'], import_from_module='ns.wifi')
    ## wifi-phy-standard.h (module 'wifi'): ns3::WifiPhyStandard [enumeration]
    module.add_enum('WifiPhyStandard', ['WIFI_PHY_STANDARD_80211a', 'WIFI_PHY_STANDARD_80211b', 'WIFI_PHY_STANDARD_80211g', 'WIFI_PHY_STANDARD_80211_10MHZ', 'WIFI_PHY_STANDARD_80211_5MHZ', 'WIFI_PHY_STANDARD_holland', 'WIFI_PHY_STANDARD_80211n_2_4GHZ', 'WIFI_PHY_STANDARD_80211n_5GHZ', 'WIFI_PHY_STANDARD_80211ac', 'WIFI_PHY_STANDARD_80211ax_2_4GHZ', 'WIFI_PHY_STANDARD_80211ax_5GHZ', 'WIFI_PHY_STANDARD_UNSPECIFIED'], import_from_module='ns.wifi')
    ## address.h (module 'network'): ns3::Address [class]
    module.add_class('Address', import_from_module='ns.network')
    ## address.h (module 'network'): ns3::Address::MaxSize_e [enumeration]
    module.add_enum('MaxSize_e', ['MAX_SIZE'], outer_class=root_module['ns3::Address'], import_from_module='ns.network')
    ## attribute-construction-list.h (module 'core'): ns3::AttributeConstructionList [class]
    module.add_class('AttributeConstructionList', import_from_module='ns.core')
    ## attribute-construction-list.h (module 'core'): ns3::AttributeConstructionList::Item [struct]
    module.add_class('Item', import_from_module='ns.core', outer_class=root_module['ns3::AttributeConstructionList'])
    typehandlers.add_type_alias(u'std::list< ns3::AttributeConstructionList::Item > const_iterator', u'ns3::AttributeConstructionList::CIterator')
    typehandlers.add_type_alias(u'std::list< ns3::AttributeConstructionList::Item > const_iterator*', u'ns3::AttributeConstructionList::CIterator*')
    typehandlers.add_type_alias(u'std::list< ns3::AttributeConstructionList::Item > const_iterator&', u'ns3::AttributeConstructionList::CIterator&')
    ## buffer.h (module 'network'): ns3::Buffer [class]
    module.add_class('Buffer', import_from_module='ns.network')
    ## buffer.h (module 'network'): ns3::Buffer::Iterator [class]
    module.add_class('Iterator', import_from_module='ns.network', outer_class=root_module['ns3::Buffer'])
    ## packet.h (module 'network'): ns3::ByteTagIterator [class]
    module.add_class('ByteTagIterator', import_from_module='ns.network')
    ## packet.h (module 'network'): ns3::ByteTagIterator::Item [class]
    module.add_class('Item', import_from_module='ns.network', outer_class=root_module['ns3::ByteTagIterator'])
    ## byte-tag-list.h (module 'network'): ns3::ByteTagList [class]
    module.add_class('ByteTagList', import_from_module='ns.network')
    ## byte-tag-list.h (module 'network'): ns3::ByteTagList::Iterator [class]
    module.add_class('Iterator', import_from_module='ns.network', outer_class=root_module['ns3::ByteTagList'])
    ## byte-tag-list.h (module 'network'): ns3::ByteTagList::Iterator::Item [struct]
    module.add_class('Item', import_from_module='ns.network', outer_class=root_module['ns3::ByteTagList::Iterator'])
    ## callback.h (module 'core'): ns3::CallbackBase [class]
    module.add_class('CallbackBase', import_from_module='ns.core')
    ## data-rate.h (module 'network'): ns3::DataRate [class]
    module.add_class('DataRate', import_from_module='ns.network')
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::AttributeAccessor> [struct]
    module.add_class('DefaultDeleter', import_from_module='ns.core', template_parameters=['ns3::AttributeAccessor'])
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::AttributeChecker> [struct]
    module.add_class('DefaultDeleter', import_from_module='ns.core', template_parameters=['ns3::AttributeChecker'])
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::AttributeValue> [struct]
    module.add_class('DefaultDeleter', import_from_module='ns.core', template_parameters=['ns3::AttributeValue'])
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::CallbackImplBase> [struct]
    module.add_class('DefaultDeleter', import_from_module='ns.core', template_parameters=['ns3::CallbackImplBase'])
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::EventImpl> [struct]
    module.add_class('DefaultDeleter', import_from_module='ns.core', template_parameters=['ns3::EventImpl'])
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::Hash::Implementation> [struct]
    module.add_class('DefaultDeleter', import_from_module='ns.core', template_parameters=['ns3::Hash::Implementation'])
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::Ipv4Route> [struct]
    module.add_class('DefaultDeleter', import_from_module='ns.core', template_parameters=['ns3::Ipv4Route'])
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::NixVector> [struct]
    module.add_class('DefaultDeleter', import_from_module='ns.core', template_parameters=['ns3::NixVector'])
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::Packet> [struct]
    module.add_class('DefaultDeleter', import_from_module='ns.core', template_parameters=['ns3::Packet'])
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::TraceSourceAccessor> [struct]
    module.add_class('DefaultDeleter', import_from_module='ns.core', template_parameters=['ns3::TraceSourceAccessor'])
    ## rushattackdsr-helper.h (module 'rushattackdsr'): ns3::RushattackdsrHelper [class]
    module.add_class('RushattackdsrHelper')
    ## rushattackdsr-main-helper.h (module 'rushattackdsr'): ns3::RushattackdsrMainHelper [class]
    module.add_class('RushattackdsrMainHelper')
    ## event-garbage-collector.h (module 'core'): ns3::EventGarbageCollector [class]
    module.add_class('EventGarbageCollector', import_from_module='ns.core')
    ## event-id.h (module 'core'): ns3::EventId [class]
    module.add_class('EventId', import_from_module='ns.core')
    ## hash.h (module 'core'): ns3::Hasher [class]
    module.add_class('Hasher', import_from_module='ns.core')
    ## inet6-socket-address.h (module 'network'): ns3::Inet6SocketAddress [class]
    module.add_class('Inet6SocketAddress', import_from_module='ns.network')
    ## inet6-socket-address.h (module 'network'): ns3::Inet6SocketAddress [class]
    root_module['ns3::Inet6SocketAddress'].implicitly_converts_to(root_module['ns3::Address'])
    ## inet-socket-address.h (module 'network'): ns3::InetSocketAddress [class]
    module.add_class('InetSocketAddress', import_from_module='ns.network')
    ## inet-socket-address.h (module 'network'): ns3::InetSocketAddress [class]
    root_module['ns3::InetSocketAddress'].implicitly_converts_to(root_module['ns3::Address'])
    ## int-to-type.h (module 'core'): ns3::IntToType<0> [struct]
    module.add_class('IntToType', import_from_module='ns.core', template_parameters=['0'])
    ## int-to-type.h (module 'core'): ns3::IntToType<0>::v_e [enumeration]
    module.add_enum('v_e', ['value'], outer_class=root_module['ns3::IntToType< 0 >'], import_from_module='ns.core')
    ## int-to-type.h (module 'core'): ns3::IntToType<1> [struct]
    module.add_class('IntToType', import_from_module='ns.core', template_parameters=['1'])
    ## int-to-type.h (module 'core'): ns3::IntToType<1>::v_e [enumeration]
    module.add_enum('v_e', ['value'], outer_class=root_module['ns3::IntToType< 1 >'], import_from_module='ns.core')
    ## int-to-type.h (module 'core'): ns3::IntToType<2> [struct]
    module.add_class('IntToType', import_from_module='ns.core', template_parameters=['2'])
    ## int-to-type.h (module 'core'): ns3::IntToType<2>::v_e [enumeration]
    module.add_enum('v_e', ['value'], outer_class=root_module['ns3::IntToType< 2 >'], import_from_module='ns.core')
    ## int-to-type.h (module 'core'): ns3::IntToType<3> [struct]
    module.add_class('IntToType', import_from_module='ns.core', template_parameters=['3'])
    ## int-to-type.h (module 'core'): ns3::IntToType<3>::v_e [enumeration]
    module.add_enum('v_e', ['value'], outer_class=root_module['ns3::IntToType< 3 >'], import_from_module='ns.core')
    ## int-to-type.h (module 'core'): ns3::IntToType<4> [struct]
    module.add_class('IntToType', import_from_module='ns.core', template_parameters=['4'])
    ## int-to-type.h (module 'core'): ns3::IntToType<4>::v_e [enumeration]
    module.add_enum('v_e', ['value'], outer_class=root_module['ns3::IntToType< 4 >'], import_from_module='ns.core')
    ## int-to-type.h (module 'core'): ns3::IntToType<5> [struct]
    module.add_class('IntToType', import_from_module='ns.core', template_parameters=['5'])
    ## int-to-type.h (module 'core'): ns3::IntToType<5>::v_e [enumeration]
    module.add_enum('v_e', ['value'], outer_class=root_module['ns3::IntToType< 5 >'], import_from_module='ns.core')
    ## int-to-type.h (module 'core'): ns3::IntToType<6> [struct]
    module.add_class('IntToType', import_from_module='ns.core', template_parameters=['6'])
    ## int-to-type.h (module 'core'): ns3::IntToType<6>::v_e [enumeration]
    module.add_enum('v_e', ['value'], outer_class=root_module['ns3::IntToType< 6 >'], import_from_module='ns.core')
    ## ipv4-address.h (module 'network'): ns3::Ipv4Address [class]
    module.add_class('Ipv4Address', import_from_module='ns.network')
    ## ipv4-address.h (module 'network'): ns3::Ipv4Address [class]
    root_module['ns3::Ipv4Address'].implicitly_converts_to(root_module['ns3::Address'])
    ## ipv4-interface-address.h (module 'internet'): ns3::Ipv4InterfaceAddress [class]
    module.add_class('Ipv4InterfaceAddress', import_from_module='ns.internet')
    ## ipv4-interface-address.h (module 'internet'): ns3::Ipv4InterfaceAddress::InterfaceAddressScope_e [enumeration]
    module.add_enum('InterfaceAddressScope_e', ['HOST', 'LINK', 'GLOBAL'], outer_class=root_module['ns3::Ipv4InterfaceAddress'], import_from_module='ns.internet')
    ## ipv4-address.h (module 'network'): ns3::Ipv4Mask [class]
    module.add_class('Ipv4Mask', import_from_module='ns.network')
    ## ipv6-address.h (module 'network'): ns3::Ipv6Address [class]
    module.add_class('Ipv6Address', import_from_module='ns.network')
    ## ipv6-address.h (module 'network'): ns3::Ipv6Address [class]
    root_module['ns3::Ipv6Address'].implicitly_converts_to(root_module['ns3::Address'])
    ## ipv6-address.h (module 'network'): ns3::Ipv6Prefix [class]
    module.add_class('Ipv6Prefix', import_from_module='ns.network')
    ## mac48-address.h (module 'network'): ns3::Mac48Address [class]
    module.add_class('Mac48Address', import_from_module='ns.network')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Mac48Address )', u'ns3::Mac48Address::TracedCallback')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Mac48Address )*', u'ns3::Mac48Address::TracedCallback*')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Mac48Address )&', u'ns3::Mac48Address::TracedCallback&')
    ## mac48-address.h (module 'network'): ns3::Mac48Address [class]
    root_module['ns3::Mac48Address'].implicitly_converts_to(root_module['ns3::Address'])
    ## mac8-address.h (module 'network'): ns3::Mac8Address [class]
    module.add_class('Mac8Address', import_from_module='ns.network')
    ## mac8-address.h (module 'network'): ns3::Mac8Address [class]
    root_module['ns3::Mac8Address'].implicitly_converts_to(root_module['ns3::Address'])
    ## node-container.h (module 'network'): ns3::NodeContainer [class]
    module.add_class('NodeContainer', import_from_module='ns.network')
    typehandlers.add_type_alias(u'std::vector< ns3::Ptr< ns3::Node > > const_iterator', u'ns3::NodeContainer::Iterator')
    typehandlers.add_type_alias(u'std::vector< ns3::Ptr< ns3::Node > > const_iterator*', u'ns3::NodeContainer::Iterator*')
    typehandlers.add_type_alias(u'std::vector< ns3::Ptr< ns3::Node > > const_iterator&', u'ns3::NodeContainer::Iterator&')
    ## non-copyable.h (module 'core'): ns3::NonCopyable [class]
    module.add_class('NonCopyable', destructor_visibility='protected', import_from_module='ns.core')
    ## object-base.h (module 'core'): ns3::ObjectBase [class]
    module.add_class('ObjectBase', allow_subclassing=True, import_from_module='ns.core')
    ## object.h (module 'core'): ns3::ObjectDeleter [struct]
    module.add_class('ObjectDeleter', import_from_module='ns.core')
    ## object-factory.h (module 'core'): ns3::ObjectFactory [class]
    module.add_class('ObjectFactory', import_from_module='ns.core')
    ## packet-metadata.h (module 'network'): ns3::PacketMetadata [class]
    module.add_class('PacketMetadata', import_from_module='ns.network')
    ## packet-metadata.h (module 'network'): ns3::PacketMetadata::Item [struct]
    module.add_class('Item', import_from_module='ns.network', outer_class=root_module['ns3::PacketMetadata'])
    ## packet-metadata.h (module 'network'): ns3::PacketMetadata::Item::ItemType [enumeration]
    module.add_enum('ItemType', ['PAYLOAD', 'HEADER', 'TRAILER'], outer_class=root_module['ns3::PacketMetadata::Item'], import_from_module='ns.network')
    ## packet-metadata.h (module 'network'): ns3::PacketMetadata::ItemIterator [class]
    module.add_class('ItemIterator', import_from_module='ns.network', outer_class=root_module['ns3::PacketMetadata'])
    ## packet.h (module 'network'): ns3::PacketTagIterator [class]
    module.add_class('PacketTagIterator', import_from_module='ns.network')
    ## packet.h (module 'network'): ns3::PacketTagIterator::Item [class]
    module.add_class('Item', import_from_module='ns.network', outer_class=root_module['ns3::PacketTagIterator'])
    ## packet-tag-list.h (module 'network'): ns3::PacketTagList [class]
    module.add_class('PacketTagList', import_from_module='ns.network')
    ## packet-tag-list.h (module 'network'): ns3::PacketTagList::TagData [struct]
    module.add_class('TagData', import_from_module='ns.network', outer_class=root_module['ns3::PacketTagList'])
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::Object, ns3::ObjectBase, ns3::ObjectDeleter> [class]
    module.add_class('SimpleRefCount', automatic_type_narrowing=True, import_from_module='ns.core', template_parameters=['ns3::Object', 'ns3::ObjectBase', 'ns3::ObjectDeleter'], parent=root_module['ns3::ObjectBase'], memory_policy=cppclass.ReferenceCountingMethodsPolicy(incref_method='Ref', decref_method='Unref', peekref_method='GetReferenceCount'))
    ## simulator.h (module 'core'): ns3::Simulator [class]
    module.add_class('Simulator', destructor_visibility='private', import_from_module='ns.core')
    ## simulator.h (module 'core'): ns3::Simulator [enumeration]
    module.add_enum('', ['NO_CONTEXT'], outer_class=root_module['ns3::Simulator'], import_from_module='ns.core')
    ## system-wall-clock-ms.h (module 'core'): ns3::SystemWallClockMs [class]
    module.add_class('SystemWallClockMs', import_from_module='ns.core')
    ## tag.h (module 'network'): ns3::Tag [class]
    module.add_class('Tag', import_from_module='ns.network', parent=root_module['ns3::ObjectBase'])
    ## tag-buffer.h (module 'network'): ns3::TagBuffer [class]
    module.add_class('TagBuffer', import_from_module='ns.network')
    ## nstime.h (module 'core'): ns3::TimeWithUnit [class]
    module.add_class('TimeWithUnit', import_from_module='ns.core')
    ## timer.h (module 'core'): ns3::Timer [class]
    module.add_class('Timer', import_from_module='ns.core')
    ## timer.h (module 'core'): ns3::Timer::DestroyPolicy [enumeration]
    module.add_enum('DestroyPolicy', ['CANCEL_ON_DESTROY', 'REMOVE_ON_DESTROY', 'CHECK_ON_DESTROY'], outer_class=root_module['ns3::Timer'], import_from_module='ns.core')
    ## timer.h (module 'core'): ns3::Timer::State [enumeration]
    module.add_enum('State', ['RUNNING', 'EXPIRED', 'SUSPENDED'], outer_class=root_module['ns3::Timer'], import_from_module='ns.core')
    ## timer-impl.h (module 'core'): ns3::TimerImpl [class]
    module.add_class('TimerImpl', allow_subclassing=True, import_from_module='ns.core')
    ## type-id.h (module 'core'): ns3::TypeId [class]
    module.add_class('TypeId', import_from_module='ns.core')
    ## type-id.h (module 'core'): ns3::TypeId::AttributeFlag [enumeration]
    module.add_enum('AttributeFlag', ['ATTR_GET', 'ATTR_SET', 'ATTR_CONSTRUCT', 'ATTR_SGC'], outer_class=root_module['ns3::TypeId'], import_from_module='ns.core')
    ## type-id.h (module 'core'): ns3::TypeId::SupportLevel [enumeration]
    module.add_enum('SupportLevel', ['SUPPORTED', 'DEPRECATED', 'OBSOLETE'], outer_class=root_module['ns3::TypeId'], import_from_module='ns.core')
    ## type-id.h (module 'core'): ns3::TypeId::AttributeInformation [struct]
    module.add_class('AttributeInformation', import_from_module='ns.core', outer_class=root_module['ns3::TypeId'])
    ## type-id.h (module 'core'): ns3::TypeId::TraceSourceInformation [struct]
    module.add_class('TraceSourceInformation', import_from_module='ns.core', outer_class=root_module['ns3::TypeId'])
    typehandlers.add_type_alias(u'uint32_t', u'ns3::TypeId::hash_t')
    typehandlers.add_type_alias(u'uint32_t*', u'ns3::TypeId::hash_t*')
    typehandlers.add_type_alias(u'uint32_t&', u'ns3::TypeId::hash_t&')
    ## wifi-mode.h (module 'wifi'): ns3::WifiMode [class]
    module.add_class('WifiMode', import_from_module='ns.wifi')
    ## wifi-mode.h (module 'wifi'): ns3::WifiModeFactory [class]
    module.add_class('WifiModeFactory', import_from_module='ns.wifi')
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStation [struct]
    module.add_class('WifiRemoteStation', import_from_module='ns.wifi')
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationInfo [class]
    module.add_class('WifiRemoteStationInfo', import_from_module='ns.wifi')
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationState [struct]
    module.add_class('WifiRemoteStationState', import_from_module='ns.wifi')
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationState [enumeration]
    module.add_enum('', ['BRAND_NEW', 'DISASSOC', 'WAIT_ASSOC_TX_OK', 'GOT_ASSOC_TX_OK'], outer_class=root_module['ns3::WifiRemoteStationState'], import_from_module='ns.wifi')
    ## empty.h (module 'core'): ns3::empty [class]
    module.add_class('empty', import_from_module='ns.core')
    ## int64x64-128.h (module 'core'): ns3::int64x64_t [class]
    module.add_class('int64x64_t', import_from_module='ns.core')
    ## int64x64-128.h (module 'core'): ns3::int64x64_t::impl_type [enumeration]
    module.add_enum('impl_type', ['int128_impl', 'cairo_impl', 'ld_impl'], outer_class=root_module['ns3::int64x64_t'], import_from_module='ns.core')
    ## chunk.h (module 'network'): ns3::Chunk [class]
    module.add_class('Chunk', import_from_module='ns.network', parent=root_module['ns3::ObjectBase'])
    ## header.h (module 'network'): ns3::Header [class]
    module.add_class('Header', import_from_module='ns.network', parent=root_module['ns3::Chunk'])
    ## icmpv4.h (module 'internet'): ns3::Icmpv4DestinationUnreachable [class]
    module.add_class('Icmpv4DestinationUnreachable', import_from_module='ns.internet', parent=root_module['ns3::Header'])
    ## icmpv4.h (module 'internet'): ns3::Icmpv4DestinationUnreachable::ErrorDestinationUnreachable_e [enumeration]
    module.add_enum('ErrorDestinationUnreachable_e', ['ICMPV4_NET_UNREACHABLE', 'ICMPV4_HOST_UNREACHABLE', 'ICMPV4_PROTOCOL_UNREACHABLE', 'ICMPV4_PORT_UNREACHABLE', 'ICMPV4_FRAG_NEEDED', 'ICMPV4_SOURCE_ROUTE_FAILED'], outer_class=root_module['ns3::Icmpv4DestinationUnreachable'], import_from_module='ns.internet')
    ## icmpv4.h (module 'internet'): ns3::Icmpv4Echo [class]
    module.add_class('Icmpv4Echo', import_from_module='ns.internet', parent=root_module['ns3::Header'])
    ## icmpv4.h (module 'internet'): ns3::Icmpv4Header [class]
    module.add_class('Icmpv4Header', import_from_module='ns.internet', parent=root_module['ns3::Header'])
    ## icmpv4.h (module 'internet'): ns3::Icmpv4Header::Type_e [enumeration]
    module.add_enum('Type_e', ['ICMPV4_ECHO_REPLY', 'ICMPV4_DEST_UNREACH', 'ICMPV4_ECHO', 'ICMPV4_TIME_EXCEEDED'], outer_class=root_module['ns3::Icmpv4Header'], import_from_module='ns.internet')
    ## icmpv4.h (module 'internet'): ns3::Icmpv4TimeExceeded [class]
    module.add_class('Icmpv4TimeExceeded', import_from_module='ns.internet', parent=root_module['ns3::Header'])
    ## icmpv4.h (module 'internet'): ns3::Icmpv4TimeExceeded::ErrorTimeExceeded_e [enumeration]
    module.add_enum('ErrorTimeExceeded_e', ['ICMPV4_TIME_TO_LIVE', 'ICMPV4_FRAGMENT_REASSEMBLY'], outer_class=root_module['ns3::Icmpv4TimeExceeded'], import_from_module='ns.internet')
    ## ipv4-header.h (module 'internet'): ns3::Ipv4Header [class]
    module.add_class('Ipv4Header', import_from_module='ns.internet', parent=root_module['ns3::Header'])
    ## ipv4-header.h (module 'internet'): ns3::Ipv4Header::DscpType [enumeration]
    module.add_enum('DscpType', ['DscpDefault', 'DSCP_CS1', 'DSCP_AF11', 'DSCP_AF12', 'DSCP_AF13', 'DSCP_CS2', 'DSCP_AF21', 'DSCP_AF22', 'DSCP_AF23', 'DSCP_CS3', 'DSCP_AF31', 'DSCP_AF32', 'DSCP_AF33', 'DSCP_CS4', 'DSCP_AF41', 'DSCP_AF42', 'DSCP_AF43', 'DSCP_CS5', 'DSCP_EF', 'DSCP_CS6', 'DSCP_CS7'], outer_class=root_module['ns3::Ipv4Header'], import_from_module='ns.internet')
    ## ipv4-header.h (module 'internet'): ns3::Ipv4Header::EcnType [enumeration]
    module.add_enum('EcnType', ['ECN_NotECT', 'ECN_ECT1', 'ECN_ECT0', 'ECN_CE'], outer_class=root_module['ns3::Ipv4Header'], import_from_module='ns.internet')
    ## ipv6-header.h (module 'internet'): ns3::Ipv6Header [class]
    module.add_class('Ipv6Header', import_from_module='ns.internet', parent=root_module['ns3::Header'])
    ## ipv6-header.h (module 'internet'): ns3::Ipv6Header::DscpType [enumeration]
    module.add_enum('DscpType', ['DscpDefault', 'DSCP_CS1', 'DSCP_AF11', 'DSCP_AF12', 'DSCP_AF13', 'DSCP_CS2', 'DSCP_AF21', 'DSCP_AF22', 'DSCP_AF23', 'DSCP_CS3', 'DSCP_AF31', 'DSCP_AF32', 'DSCP_AF33', 'DSCP_CS4', 'DSCP_AF41', 'DSCP_AF42', 'DSCP_AF43', 'DSCP_CS5', 'DSCP_EF', 'DSCP_CS6', 'DSCP_CS7'], outer_class=root_module['ns3::Ipv6Header'], import_from_module='ns.internet')
    ## ipv6-header.h (module 'internet'): ns3::Ipv6Header::NextHeader_e [enumeration]
    module.add_enum('NextHeader_e', ['IPV6_EXT_HOP_BY_HOP', 'IPV6_IPV4', 'IPV6_TCP', 'IPV6_UDP', 'IPV6_IPV6', 'IPV6_EXT_ROUTING', 'IPV6_EXT_FRAGMENTATION', 'IPV6_EXT_CONFIDENTIALITY', 'IPV6_EXT_AUTHENTIFICATION', 'IPV6_ICMPV6', 'IPV6_EXT_END', 'IPV6_EXT_DESTINATION', 'IPV6_SCTP', 'IPV6_EXT_MOBILITY', 'IPV6_UDP_LITE'], outer_class=root_module['ns3::Ipv6Header'], import_from_module='ns.internet')
    ## ipv6-header.h (module 'internet'): ns3::Ipv6Header::EcnType [enumeration]
    module.add_enum('EcnType', ['ECN_NotECT', 'ECN_ECT1', 'ECN_ECT0', 'ECN_CE'], outer_class=root_module['ns3::Ipv6Header'], import_from_module='ns.internet')
    ## object.h (module 'core'): ns3::Object [class]
    module.add_class('Object', import_from_module='ns.core', parent=root_module['ns3::SimpleRefCount< ns3::Object, ns3::ObjectBase, ns3::ObjectDeleter >'])
    ## object.h (module 'core'): ns3::Object::AggregateIterator [class]
    module.add_class('AggregateIterator', import_from_module='ns.core', outer_class=root_module['ns3::Object'])
    ## random-variable-stream.h (module 'core'): ns3::RandomVariableStream [class]
    module.add_class('RandomVariableStream', import_from_module='ns.core', parent=root_module['ns3::Object'])
    ## random-variable-stream.h (module 'core'): ns3::SequentialRandomVariable [class]
    module.add_class('SequentialRandomVariable', import_from_module='ns.core', parent=root_module['ns3::RandomVariableStream'])
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::AttributeAccessor, ns3::empty, ns3::DefaultDeleter<ns3::AttributeAccessor> > [class]
    module.add_class('SimpleRefCount', automatic_type_narrowing=True, import_from_module='ns.core', template_parameters=['ns3::AttributeAccessor', 'ns3::empty', 'ns3::DefaultDeleter<ns3::AttributeAccessor>'], parent=root_module['ns3::empty'], memory_policy=cppclass.ReferenceCountingMethodsPolicy(incref_method='Ref', decref_method='Unref', peekref_method='GetReferenceCount'))
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::AttributeChecker, ns3::empty, ns3::DefaultDeleter<ns3::AttributeChecker> > [class]
    module.add_class('SimpleRefCount', automatic_type_narrowing=True, import_from_module='ns.core', template_parameters=['ns3::AttributeChecker', 'ns3::empty', 'ns3::DefaultDeleter<ns3::AttributeChecker>'], parent=root_module['ns3::empty'], memory_policy=cppclass.ReferenceCountingMethodsPolicy(incref_method='Ref', decref_method='Unref', peekref_method='GetReferenceCount'))
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::AttributeValue, ns3::empty, ns3::DefaultDeleter<ns3::AttributeValue> > [class]
    module.add_class('SimpleRefCount', automatic_type_narrowing=True, import_from_module='ns.core', template_parameters=['ns3::AttributeValue', 'ns3::empty', 'ns3::DefaultDeleter<ns3::AttributeValue>'], parent=root_module['ns3::empty'], memory_policy=cppclass.ReferenceCountingMethodsPolicy(incref_method='Ref', decref_method='Unref', peekref_method='GetReferenceCount'))
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::CallbackImplBase, ns3::empty, ns3::DefaultDeleter<ns3::CallbackImplBase> > [class]
    module.add_class('SimpleRefCount', automatic_type_narrowing=True, import_from_module='ns.core', template_parameters=['ns3::CallbackImplBase', 'ns3::empty', 'ns3::DefaultDeleter<ns3::CallbackImplBase>'], parent=root_module['ns3::empty'], memory_policy=cppclass.ReferenceCountingMethodsPolicy(incref_method='Ref', decref_method='Unref', peekref_method='GetReferenceCount'))
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::EventImpl, ns3::empty, ns3::DefaultDeleter<ns3::EventImpl> > [class]
    module.add_class('SimpleRefCount', automatic_type_narrowing=True, import_from_module='ns.core', template_parameters=['ns3::EventImpl', 'ns3::empty', 'ns3::DefaultDeleter<ns3::EventImpl>'], parent=root_module['ns3::empty'], memory_policy=cppclass.ReferenceCountingMethodsPolicy(incref_method='Ref', decref_method='Unref', peekref_method='GetReferenceCount'))
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::Hash::Implementation, ns3::empty, ns3::DefaultDeleter<ns3::Hash::Implementation> > [class]
    module.add_class('SimpleRefCount', automatic_type_narrowing=True, import_from_module='ns.core', template_parameters=['ns3::Hash::Implementation', 'ns3::empty', 'ns3::DefaultDeleter<ns3::Hash::Implementation>'], parent=root_module['ns3::empty'], memory_policy=cppclass.ReferenceCountingMethodsPolicy(incref_method='Ref', decref_method='Unref', peekref_method='GetReferenceCount'))
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::Ipv4MulticastRoute, ns3::empty, ns3::DefaultDeleter<ns3::Ipv4MulticastRoute> > [class]
    module.add_class('SimpleRefCount', automatic_type_narrowing=True, import_from_module='ns.core', template_parameters=['ns3::Ipv4MulticastRoute', 'ns3::empty', 'ns3::DefaultDeleter<ns3::Ipv4MulticastRoute>'], parent=root_module['ns3::empty'], memory_policy=cppclass.ReferenceCountingMethodsPolicy(incref_method='Ref', decref_method='Unref', peekref_method='GetReferenceCount'))
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::Ipv4Route, ns3::empty, ns3::DefaultDeleter<ns3::Ipv4Route> > [class]
    module.add_class('SimpleRefCount', automatic_type_narrowing=True, import_from_module='ns.core', template_parameters=['ns3::Ipv4Route', 'ns3::empty', 'ns3::DefaultDeleter<ns3::Ipv4Route>'], parent=root_module['ns3::empty'], memory_policy=cppclass.ReferenceCountingMethodsPolicy(incref_method='Ref', decref_method='Unref', peekref_method='GetReferenceCount'))
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::NixVector, ns3::empty, ns3::DefaultDeleter<ns3::NixVector> > [class]
    module.add_class('SimpleRefCount', automatic_type_narrowing=True, import_from_module='ns.core', template_parameters=['ns3::NixVector', 'ns3::empty', 'ns3::DefaultDeleter<ns3::NixVector>'], parent=root_module['ns3::empty'], memory_policy=cppclass.ReferenceCountingMethodsPolicy(incref_method='Ref', decref_method='Unref', peekref_method='GetReferenceCount'))
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::OutputStreamWrapper, ns3::empty, ns3::DefaultDeleter<ns3::OutputStreamWrapper> > [class]
    module.add_class('SimpleRefCount', automatic_type_narrowing=True, import_from_module='ns.core', template_parameters=['ns3::OutputStreamWrapper', 'ns3::empty', 'ns3::DefaultDeleter<ns3::OutputStreamWrapper>'], parent=root_module['ns3::empty'], memory_policy=cppclass.ReferenceCountingMethodsPolicy(incref_method='Ref', decref_method='Unref', peekref_method='GetReferenceCount'))
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::Packet, ns3::empty, ns3::DefaultDeleter<ns3::Packet> > [class]
    module.add_class('SimpleRefCount', automatic_type_narrowing=True, import_from_module='ns.core', template_parameters=['ns3::Packet', 'ns3::empty', 'ns3::DefaultDeleter<ns3::Packet>'], parent=root_module['ns3::empty'], memory_policy=cppclass.ReferenceCountingMethodsPolicy(incref_method='Ref', decref_method='Unref', peekref_method='GetReferenceCount'))
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::TraceSourceAccessor, ns3::empty, ns3::DefaultDeleter<ns3::TraceSourceAccessor> > [class]
    module.add_class('SimpleRefCount', automatic_type_narrowing=True, import_from_module='ns.core', template_parameters=['ns3::TraceSourceAccessor', 'ns3::empty', 'ns3::DefaultDeleter<ns3::TraceSourceAccessor>'], parent=root_module['ns3::empty'], memory_policy=cppclass.ReferenceCountingMethodsPolicy(incref_method='Ref', decref_method='Unref', peekref_method='GetReferenceCount'))
    ## socket.h (module 'network'): ns3::Socket [class]
    module.add_class('Socket', import_from_module='ns.network', parent=root_module['ns3::Object'])
    ## socket.h (module 'network'): ns3::Socket::SocketErrno [enumeration]
    module.add_enum('SocketErrno', ['ERROR_NOTERROR', 'ERROR_ISCONN', 'ERROR_NOTCONN', 'ERROR_MSGSIZE', 'ERROR_AGAIN', 'ERROR_SHUTDOWN', 'ERROR_OPNOTSUPP', 'ERROR_AFNOSUPPORT', 'ERROR_INVAL', 'ERROR_BADF', 'ERROR_NOROUTETOHOST', 'ERROR_NODEV', 'ERROR_ADDRNOTAVAIL', 'ERROR_ADDRINUSE', 'SOCKET_ERRNO_LAST'], outer_class=root_module['ns3::Socket'], import_from_module='ns.network')
    ## socket.h (module 'network'): ns3::Socket::SocketType [enumeration]
    module.add_enum('SocketType', ['NS3_SOCK_STREAM', 'NS3_SOCK_SEQPACKET', 'NS3_SOCK_DGRAM', 'NS3_SOCK_RAW'], outer_class=root_module['ns3::Socket'], import_from_module='ns.network')
    ## socket.h (module 'network'): ns3::Socket::SocketPriority [enumeration]
    module.add_enum('SocketPriority', ['NS3_PRIO_BESTEFFORT', 'NS3_PRIO_FILLER', 'NS3_PRIO_BULK', 'NS3_PRIO_INTERACTIVE_BULK', 'NS3_PRIO_INTERACTIVE', 'NS3_PRIO_CONTROL'], outer_class=root_module['ns3::Socket'], import_from_module='ns.network')
    ## socket.h (module 'network'): ns3::Socket::Ipv6MulticastFilterMode [enumeration]
    module.add_enum('Ipv6MulticastFilterMode', ['INCLUDE', 'EXCLUDE'], outer_class=root_module['ns3::Socket'], import_from_module='ns.network')
    ## socket.h (module 'network'): ns3::SocketIpTosTag [class]
    module.add_class('SocketIpTosTag', import_from_module='ns.network', parent=root_module['ns3::Tag'])
    ## socket.h (module 'network'): ns3::SocketIpTtlTag [class]
    module.add_class('SocketIpTtlTag', import_from_module='ns.network', parent=root_module['ns3::Tag'])
    ## socket.h (module 'network'): ns3::SocketIpv6HopLimitTag [class]
    module.add_class('SocketIpv6HopLimitTag', import_from_module='ns.network', parent=root_module['ns3::Tag'])
    ## socket.h (module 'network'): ns3::SocketIpv6TclassTag [class]
    module.add_class('SocketIpv6TclassTag', import_from_module='ns.network', parent=root_module['ns3::Tag'])
    ## socket.h (module 'network'): ns3::SocketPriorityTag [class]
    module.add_class('SocketPriorityTag', import_from_module='ns.network', parent=root_module['ns3::Tag'])
    ## socket.h (module 'network'): ns3::SocketSetDontFragmentTag [class]
    module.add_class('SocketSetDontFragmentTag', import_from_module='ns.network', parent=root_module['ns3::Tag'])
    ## nstime.h (module 'core'): ns3::Time [class]
    module.add_class('Time', import_from_module='ns.core')
    ## nstime.h (module 'core'): ns3::Time::Unit [enumeration]
    module.add_enum('Unit', ['Y', 'D', 'H', 'MIN', 'S', 'MS', 'US', 'NS', 'PS', 'FS', 'LAST'], outer_class=root_module['ns3::Time'], import_from_module='ns.core')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Time )', u'ns3::Time::TracedCallback')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Time )*', u'ns3::Time::TracedCallback*')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Time )&', u'ns3::Time::TracedCallback&')
    ## nstime.h (module 'core'): ns3::Time [class]
    root_module['ns3::Time'].implicitly_converts_to(root_module['ns3::int64x64_t'])
    ## trace-source-accessor.h (module 'core'): ns3::TraceSourceAccessor [class]
    module.add_class('TraceSourceAccessor', import_from_module='ns.core', parent=root_module['ns3::SimpleRefCount< ns3::TraceSourceAccessor, ns3::empty, ns3::DefaultDeleter<ns3::TraceSourceAccessor> >'])
    ## trailer.h (module 'network'): ns3::Trailer [class]
    module.add_class('Trailer', import_from_module='ns.network', parent=root_module['ns3::Chunk'])
    ## random-variable-stream.h (module 'core'): ns3::TriangularRandomVariable [class]
    module.add_class('TriangularRandomVariable', import_from_module='ns.core', parent=root_module['ns3::RandomVariableStream'])
    ## random-variable-stream.h (module 'core'): ns3::UniformRandomVariable [class]
    module.add_class('UniformRandomVariable', import_from_module='ns.core', parent=root_module['ns3::RandomVariableStream'])
    ## random-variable-stream.h (module 'core'): ns3::WeibullRandomVariable [class]
    module.add_class('WeibullRandomVariable', import_from_module='ns.core', parent=root_module['ns3::RandomVariableStream'])
    ## wifi-mac.h (module 'wifi'): ns3::WifiMac [class]
    module.add_class('WifiMac', import_from_module='ns.wifi', parent=root_module['ns3::Object'])
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationManager [class]
    module.add_class('WifiRemoteStationManager', import_from_module='ns.wifi', parent=root_module['ns3::Object'])
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationManager::ProtectionMode [enumeration]
    module.add_enum('ProtectionMode', ['RTS_CTS', 'CTS_TO_SELF'], outer_class=root_module['ns3::WifiRemoteStationManager'], import_from_module='ns.wifi')
    typehandlers.add_type_alias(u'void ( * ) ( double, double, ns3::Mac48Address )', u'ns3::WifiRemoteStationManager::PowerChangeTracedCallback')
    typehandlers.add_type_alias(u'void ( * ) ( double, double, ns3::Mac48Address )*', u'ns3::WifiRemoteStationManager::PowerChangeTracedCallback*')
    typehandlers.add_type_alias(u'void ( * ) ( double, double, ns3::Mac48Address )&', u'ns3::WifiRemoteStationManager::PowerChangeTracedCallback&')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::DataRate, ns3::DataRate, ns3::Mac48Address )', u'ns3::WifiRemoteStationManager::RateChangeTracedCallback')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::DataRate, ns3::DataRate, ns3::Mac48Address )*', u'ns3::WifiRemoteStationManager::RateChangeTracedCallback*')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::DataRate, ns3::DataRate, ns3::Mac48Address )&', u'ns3::WifiRemoteStationManager::RateChangeTracedCallback&')
    ## random-variable-stream.h (module 'core'): ns3::ZetaRandomVariable [class]
    module.add_class('ZetaRandomVariable', import_from_module='ns.core', parent=root_module['ns3::RandomVariableStream'])
    ## random-variable-stream.h (module 'core'): ns3::ZipfRandomVariable [class]
    module.add_class('ZipfRandomVariable', import_from_module='ns.core', parent=root_module['ns3::RandomVariableStream'])
    ## arp-cache.h (module 'internet'): ns3::ArpCache [class]
    module.add_class('ArpCache', import_from_module='ns.internet', parent=root_module['ns3::Object'])
    ## arp-cache.h (module 'internet'): ns3::ArpCache::Entry [class]
    module.add_class('Entry', import_from_module='ns.internet', outer_class=root_module['ns3::ArpCache'])
    typehandlers.add_type_alias(u'std::pair< ns3::Ptr< ns3::Packet >, ns3::Ipv4Header >', u'ns3::ArpCache::Ipv4PayloadHeaderPair')
    typehandlers.add_type_alias(u'std::pair< ns3::Ptr< ns3::Packet >, ns3::Ipv4Header >*', u'ns3::ArpCache::Ipv4PayloadHeaderPair*')
    typehandlers.add_type_alias(u'std::pair< ns3::Ptr< ns3::Packet >, ns3::Ipv4Header >&', u'ns3::ArpCache::Ipv4PayloadHeaderPair&')
    ## attribute.h (module 'core'): ns3::AttributeAccessor [class]
    module.add_class('AttributeAccessor', import_from_module='ns.core', parent=root_module['ns3::SimpleRefCount< ns3::AttributeAccessor, ns3::empty, ns3::DefaultDeleter<ns3::AttributeAccessor> >'])
    ## attribute.h (module 'core'): ns3::AttributeChecker [class]
    module.add_class('AttributeChecker', allow_subclassing=False, automatic_type_narrowing=True, import_from_module='ns.core', parent=root_module['ns3::SimpleRefCount< ns3::AttributeChecker, ns3::empty, ns3::DefaultDeleter<ns3::AttributeChecker> >'])
    ## attribute.h (module 'core'): ns3::AttributeValue [class]
    module.add_class('AttributeValue', allow_subclassing=False, automatic_type_narrowing=True, import_from_module='ns.core', parent=root_module['ns3::SimpleRefCount< ns3::AttributeValue, ns3::empty, ns3::DefaultDeleter<ns3::AttributeValue> >'])
    ## callback.h (module 'core'): ns3::CallbackChecker [class]
    module.add_class('CallbackChecker', import_from_module='ns.core', parent=root_module['ns3::AttributeChecker'])
    ## callback.h (module 'core'): ns3::CallbackImplBase [class]
    module.add_class('CallbackImplBase', import_from_module='ns.core', parent=root_module['ns3::SimpleRefCount< ns3::CallbackImplBase, ns3::empty, ns3::DefaultDeleter<ns3::CallbackImplBase> >'])
    ## callback.h (module 'core'): ns3::CallbackValue [class]
    module.add_class('CallbackValue', import_from_module='ns.core', parent=root_module['ns3::AttributeValue'])
    ## random-variable-stream.h (module 'core'): ns3::ConstantRandomVariable [class]
    module.add_class('ConstantRandomVariable', import_from_module='ns.core', parent=root_module['ns3::RandomVariableStream'])
    ## data-rate.h (module 'network'): ns3::DataRateChecker [class]
    module.add_class('DataRateChecker', import_from_module='ns.network', parent=root_module['ns3::AttributeChecker'])
    ## data-rate.h (module 'network'): ns3::DataRateValue [class]
    module.add_class('DataRateValue', import_from_module='ns.network', parent=root_module['ns3::AttributeValue'])
    ## random-variable-stream.h (module 'core'): ns3::DeterministicRandomVariable [class]
    module.add_class('DeterministicRandomVariable', import_from_module='ns.core', parent=root_module['ns3::RandomVariableStream'])
    ## random-variable-stream.h (module 'core'): ns3::EmpiricalRandomVariable [class]
    module.add_class('EmpiricalRandomVariable', import_from_module='ns.core', parent=root_module['ns3::RandomVariableStream'])
    ## attribute.h (module 'core'): ns3::EmptyAttributeAccessor [class]
    module.add_class('EmptyAttributeAccessor', import_from_module='ns.core', parent=root_module['ns3::AttributeAccessor'])
    ## attribute.h (module 'core'): ns3::EmptyAttributeChecker [class]
    module.add_class('EmptyAttributeChecker', import_from_module='ns.core', parent=root_module['ns3::AttributeChecker'])
    ## attribute.h (module 'core'): ns3::EmptyAttributeValue [class]
    module.add_class('EmptyAttributeValue', import_from_module='ns.core', parent=root_module['ns3::AttributeValue'])
    ## enum.h (module 'core'): ns3::EnumChecker [class]
    module.add_class('EnumChecker', import_from_module='ns.core', parent=root_module['ns3::AttributeChecker'])
    ## enum.h (module 'core'): ns3::EnumValue [class]
    module.add_class('EnumValue', import_from_module='ns.core', parent=root_module['ns3::AttributeValue'])
    ## random-variable-stream.h (module 'core'): ns3::ErlangRandomVariable [class]
    module.add_class('ErlangRandomVariable', import_from_module='ns.core', parent=root_module['ns3::RandomVariableStream'])
    ## event-impl.h (module 'core'): ns3::EventImpl [class]
    module.add_class('EventImpl', import_from_module='ns.core', parent=root_module['ns3::SimpleRefCount< ns3::EventImpl, ns3::empty, ns3::DefaultDeleter<ns3::EventImpl> >'])
    ## random-variable-stream.h (module 'core'): ns3::ExponentialRandomVariable [class]
    module.add_class('ExponentialRandomVariable', import_from_module='ns.core', parent=root_module['ns3::RandomVariableStream'])
    ## random-variable-stream.h (module 'core'): ns3::GammaRandomVariable [class]
    module.add_class('GammaRandomVariable', import_from_module='ns.core', parent=root_module['ns3::RandomVariableStream'])
    ## ip-l4-protocol.h (module 'internet'): ns3::IpL4Protocol [class]
    module.add_class('IpL4Protocol', import_from_module='ns.internet', parent=root_module['ns3::Object'])
    ## ip-l4-protocol.h (module 'internet'): ns3::IpL4Protocol::RxStatus [enumeration]
    module.add_enum('RxStatus', ['RX_OK', 'RX_CSUM_FAILED', 'RX_ENDPOINT_CLOSED', 'RX_ENDPOINT_UNREACH'], outer_class=root_module['ns3::IpL4Protocol'], import_from_module='ns.internet')
    typehandlers.add_type_alias(u'ns3::Callback< void, ns3::Ptr< ns3::Packet >, ns3::Ipv4Address, ns3::Ipv4Address, unsigned char, ns3::Ptr< ns3::Ipv4Route >, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', u'ns3::IpL4Protocol::DownTargetCallback')
    typehandlers.add_type_alias(u'ns3::Callback< void, ns3::Ptr< ns3::Packet >, ns3::Ipv4Address, ns3::Ipv4Address, unsigned char, ns3::Ptr< ns3::Ipv4Route >, ns3::empty, ns3::empty, ns3::empty, ns3::empty >*', u'ns3::IpL4Protocol::DownTargetCallback*')
    typehandlers.add_type_alias(u'ns3::Callback< void, ns3::Ptr< ns3::Packet >, ns3::Ipv4Address, ns3::Ipv4Address, unsigned char, ns3::Ptr< ns3::Ipv4Route >, ns3::empty, ns3::empty, ns3::empty, ns3::empty >&', u'ns3::IpL4Protocol::DownTargetCallback&')
    typehandlers.add_type_alias(u'ns3::Callback< void, ns3::Ptr< ns3::Packet >, ns3::Ipv6Address, ns3::Ipv6Address, unsigned char, ns3::Ptr< ns3::Ipv6Route >, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', u'ns3::IpL4Protocol::DownTargetCallback6')
    typehandlers.add_type_alias(u'ns3::Callback< void, ns3::Ptr< ns3::Packet >, ns3::Ipv6Address, ns3::Ipv6Address, unsigned char, ns3::Ptr< ns3::Ipv6Route >, ns3::empty, ns3::empty, ns3::empty, ns3::empty >*', u'ns3::IpL4Protocol::DownTargetCallback6*')
    typehandlers.add_type_alias(u'ns3::Callback< void, ns3::Ptr< ns3::Packet >, ns3::Ipv6Address, ns3::Ipv6Address, unsigned char, ns3::Ptr< ns3::Ipv6Route >, ns3::empty, ns3::empty, ns3::empty, ns3::empty >&', u'ns3::IpL4Protocol::DownTargetCallback6&')
    ## ipv4.h (module 'internet'): ns3::Ipv4 [class]
    module.add_class('Ipv4', import_from_module='ns.internet', parent=root_module['ns3::Object'])
    ## ipv4-address.h (module 'network'): ns3::Ipv4AddressChecker [class]
    module.add_class('Ipv4AddressChecker', import_from_module='ns.network', parent=root_module['ns3::AttributeChecker'])
    ## ipv4-address.h (module 'network'): ns3::Ipv4AddressValue [class]
    module.add_class('Ipv4AddressValue', import_from_module='ns.network', parent=root_module['ns3::AttributeValue'])
    ## ipv4-interface.h (module 'internet'): ns3::Ipv4Interface [class]
    module.add_class('Ipv4Interface', import_from_module='ns.internet', parent=root_module['ns3::Object'])
    ## ipv4-l3-protocol.h (module 'internet'): ns3::Ipv4L3Protocol [class]
    module.add_class('Ipv4L3Protocol', import_from_module='ns.internet', parent=root_module['ns3::Ipv4'])
    ## ipv4-l3-protocol.h (module 'internet'): ns3::Ipv4L3Protocol::DropReason [enumeration]
    module.add_enum('DropReason', ['DROP_TTL_EXPIRED', 'DROP_NO_ROUTE', 'DROP_BAD_CHECKSUM', 'DROP_INTERFACE_DOWN', 'DROP_ROUTE_ERROR', 'DROP_FRAGMENT_TIMEOUT'], outer_class=root_module['ns3::Ipv4L3Protocol'], import_from_module='ns.internet')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Ipv4Header const &, ns3::Ptr< ns3::Packet const >, uint32_t )', u'ns3::Ipv4L3Protocol::SentTracedCallback')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Ipv4Header const &, ns3::Ptr< ns3::Packet const >, uint32_t )*', u'ns3::Ipv4L3Protocol::SentTracedCallback*')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Ipv4Header const &, ns3::Ptr< ns3::Packet const >, uint32_t )&', u'ns3::Ipv4L3Protocol::SentTracedCallback&')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Ptr< ns3::Packet const >, ns3::Ptr< ns3::Ipv4 >, uint32_t )', u'ns3::Ipv4L3Protocol::TxRxTracedCallback')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Ptr< ns3::Packet const >, ns3::Ptr< ns3::Ipv4 >, uint32_t )*', u'ns3::Ipv4L3Protocol::TxRxTracedCallback*')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Ptr< ns3::Packet const >, ns3::Ptr< ns3::Ipv4 >, uint32_t )&', u'ns3::Ipv4L3Protocol::TxRxTracedCallback&')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Ipv4Header const &, ns3::Ptr< ns3::Packet const >, ns3::Ipv4L3Protocol::DropReason, ns3::Ptr< ns3::Ipv4 >, uint32_t )', u'ns3::Ipv4L3Protocol::DropTracedCallback')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Ipv4Header const &, ns3::Ptr< ns3::Packet const >, ns3::Ipv4L3Protocol::DropReason, ns3::Ptr< ns3::Ipv4 >, uint32_t )*', u'ns3::Ipv4L3Protocol::DropTracedCallback*')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Ipv4Header const &, ns3::Ptr< ns3::Packet const >, ns3::Ipv4L3Protocol::DropReason, ns3::Ptr< ns3::Ipv4 >, uint32_t )&', u'ns3::Ipv4L3Protocol::DropTracedCallback&')
    ## ipv4-address.h (module 'network'): ns3::Ipv4MaskChecker [class]
    module.add_class('Ipv4MaskChecker', import_from_module='ns.network', parent=root_module['ns3::AttributeChecker'])
    ## ipv4-address.h (module 'network'): ns3::Ipv4MaskValue [class]
    module.add_class('Ipv4MaskValue', import_from_module='ns.network', parent=root_module['ns3::AttributeValue'])
    ## ipv4-route.h (module 'internet'): ns3::Ipv4MulticastRoute [class]
    module.add_class('Ipv4MulticastRoute', import_from_module='ns.internet', parent=root_module['ns3::SimpleRefCount< ns3::Ipv4MulticastRoute, ns3::empty, ns3::DefaultDeleter<ns3::Ipv4MulticastRoute> >'])
    ## ipv4-route.h (module 'internet'): ns3::Ipv4Route [class]
    module.add_class('Ipv4Route', import_from_module='ns.internet', parent=root_module['ns3::SimpleRefCount< ns3::Ipv4Route, ns3::empty, ns3::DefaultDeleter<ns3::Ipv4Route> >'])
    ## ipv4-routing-protocol.h (module 'internet'): ns3::Ipv4RoutingProtocol [class]
    module.add_class('Ipv4RoutingProtocol', import_from_module='ns.internet', parent=root_module['ns3::Object'])
    typehandlers.add_type_alias(u'ns3::Callback< void, ns3::Ptr< ns3::Ipv4Route >, ns3::Ptr< ns3::Packet const >, ns3::Ipv4Header const &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', u'ns3::Ipv4RoutingProtocol::UnicastForwardCallback')
    typehandlers.add_type_alias(u'ns3::Callback< void, ns3::Ptr< ns3::Ipv4Route >, ns3::Ptr< ns3::Packet const >, ns3::Ipv4Header const &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >*', u'ns3::Ipv4RoutingProtocol::UnicastForwardCallback*')
    typehandlers.add_type_alias(u'ns3::Callback< void, ns3::Ptr< ns3::Ipv4Route >, ns3::Ptr< ns3::Packet const >, ns3::Ipv4Header const &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >&', u'ns3::Ipv4RoutingProtocol::UnicastForwardCallback&')
    typehandlers.add_type_alias(u'ns3::Callback< void, ns3::Ptr< ns3::Ipv4MulticastRoute >, ns3::Ptr< ns3::Packet const >, ns3::Ipv4Header const &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', u'ns3::Ipv4RoutingProtocol::MulticastForwardCallback')
    typehandlers.add_type_alias(u'ns3::Callback< void, ns3::Ptr< ns3::Ipv4MulticastRoute >, ns3::Ptr< ns3::Packet const >, ns3::Ipv4Header const &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >*', u'ns3::Ipv4RoutingProtocol::MulticastForwardCallback*')
    typehandlers.add_type_alias(u'ns3::Callback< void, ns3::Ptr< ns3::Ipv4MulticastRoute >, ns3::Ptr< ns3::Packet const >, ns3::Ipv4Header const &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >&', u'ns3::Ipv4RoutingProtocol::MulticastForwardCallback&')
    typehandlers.add_type_alias(u'ns3::Callback< void, ns3::Ptr< ns3::Packet const >, ns3::Ipv4Header const &, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', u'ns3::Ipv4RoutingProtocol::LocalDeliverCallback')
    typehandlers.add_type_alias(u'ns3::Callback< void, ns3::Ptr< ns3::Packet const >, ns3::Ipv4Header const &, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >*', u'ns3::Ipv4RoutingProtocol::LocalDeliverCallback*')
    typehandlers.add_type_alias(u'ns3::Callback< void, ns3::Ptr< ns3::Packet const >, ns3::Ipv4Header const &, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >&', u'ns3::Ipv4RoutingProtocol::LocalDeliverCallback&')
    typehandlers.add_type_alias(u'ns3::Callback< void, ns3::Ptr< ns3::Packet const >, ns3::Ipv4Header const &, ns3::Socket::SocketErrno, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', u'ns3::Ipv4RoutingProtocol::ErrorCallback')
    typehandlers.add_type_alias(u'ns3::Callback< void, ns3::Ptr< ns3::Packet const >, ns3::Ipv4Header const &, ns3::Socket::SocketErrno, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >*', u'ns3::Ipv4RoutingProtocol::ErrorCallback*')
    typehandlers.add_type_alias(u'ns3::Callback< void, ns3::Ptr< ns3::Packet const >, ns3::Ipv4Header const &, ns3::Socket::SocketErrno, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >&', u'ns3::Ipv4RoutingProtocol::ErrorCallback&')
    ## ipv6-address.h (module 'network'): ns3::Ipv6AddressChecker [class]
    module.add_class('Ipv6AddressChecker', import_from_module='ns.network', parent=root_module['ns3::AttributeChecker'])
    ## ipv6-address.h (module 'network'): ns3::Ipv6AddressValue [class]
    module.add_class('Ipv6AddressValue', import_from_module='ns.network', parent=root_module['ns3::AttributeValue'])
    ## ipv6-address.h (module 'network'): ns3::Ipv6PrefixChecker [class]
    module.add_class('Ipv6PrefixChecker', import_from_module='ns.network', parent=root_module['ns3::AttributeChecker'])
    ## ipv6-address.h (module 'network'): ns3::Ipv6PrefixValue [class]
    module.add_class('Ipv6PrefixValue', import_from_module='ns.network', parent=root_module['ns3::AttributeValue'])
    ## random-variable-stream.h (module 'core'): ns3::LogNormalRandomVariable [class]
    module.add_class('LogNormalRandomVariable', import_from_module='ns.core', parent=root_module['ns3::RandomVariableStream'])
    ## mac48-address.h (module 'network'): ns3::Mac48AddressChecker [class]
    module.add_class('Mac48AddressChecker', import_from_module='ns.network', parent=root_module['ns3::AttributeChecker'])
    ## mac48-address.h (module 'network'): ns3::Mac48AddressValue [class]
    module.add_class('Mac48AddressValue', import_from_module='ns.network', parent=root_module['ns3::AttributeValue'])
    ## net-device.h (module 'network'): ns3::NetDevice [class]
    module.add_class('NetDevice', import_from_module='ns.network', parent=root_module['ns3::Object'])
    ## net-device.h (module 'network'): ns3::NetDevice::PacketType [enumeration]
    module.add_enum('PacketType', ['PACKET_HOST', 'NS3_PACKET_HOST', 'PACKET_BROADCAST', 'NS3_PACKET_BROADCAST', 'PACKET_MULTICAST', 'NS3_PACKET_MULTICAST', 'PACKET_OTHERHOST', 'NS3_PACKET_OTHERHOST'], outer_class=root_module['ns3::NetDevice'], import_from_module='ns.network')
    typehandlers.add_type_alias(u'void ( * ) (  )', u'ns3::NetDevice::LinkChangeTracedCallback')
    typehandlers.add_type_alias(u'void ( * ) (  )*', u'ns3::NetDevice::LinkChangeTracedCallback*')
    typehandlers.add_type_alias(u'void ( * ) (  )&', u'ns3::NetDevice::LinkChangeTracedCallback&')
    typehandlers.add_type_alias(u'ns3::Callback< bool, ns3::Ptr< ns3::NetDevice >, ns3::Ptr< ns3::Packet const >, unsigned short, ns3::Address const &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', u'ns3::NetDevice::ReceiveCallback')
    typehandlers.add_type_alias(u'ns3::Callback< bool, ns3::Ptr< ns3::NetDevice >, ns3::Ptr< ns3::Packet const >, unsigned short, ns3::Address const &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >*', u'ns3::NetDevice::ReceiveCallback*')
    typehandlers.add_type_alias(u'ns3::Callback< bool, ns3::Ptr< ns3::NetDevice >, ns3::Ptr< ns3::Packet const >, unsigned short, ns3::Address const &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >&', u'ns3::NetDevice::ReceiveCallback&')
    typehandlers.add_type_alias(u'ns3::Callback< bool, ns3::Ptr< ns3::NetDevice >, ns3::Ptr< ns3::Packet const >, unsigned short, ns3::Address const &, ns3::Address const &, ns3::NetDevice::PacketType, ns3::empty, ns3::empty, ns3::empty >', u'ns3::NetDevice::PromiscReceiveCallback')
    typehandlers.add_type_alias(u'ns3::Callback< bool, ns3::Ptr< ns3::NetDevice >, ns3::Ptr< ns3::Packet const >, unsigned short, ns3::Address const &, ns3::Address const &, ns3::NetDevice::PacketType, ns3::empty, ns3::empty, ns3::empty >*', u'ns3::NetDevice::PromiscReceiveCallback*')
    typehandlers.add_type_alias(u'ns3::Callback< bool, ns3::Ptr< ns3::NetDevice >, ns3::Ptr< ns3::Packet const >, unsigned short, ns3::Address const &, ns3::Address const &, ns3::NetDevice::PacketType, ns3::empty, ns3::empty, ns3::empty >&', u'ns3::NetDevice::PromiscReceiveCallback&')
    ## nix-vector.h (module 'network'): ns3::NixVector [class]
    module.add_class('NixVector', import_from_module='ns.network', parent=root_module['ns3::SimpleRefCount< ns3::NixVector, ns3::empty, ns3::DefaultDeleter<ns3::NixVector> >'])
    ## node.h (module 'network'): ns3::Node [class]
    module.add_class('Node', import_from_module='ns.network', parent=root_module['ns3::Object'])
    typehandlers.add_type_alias(u'ns3::Callback< void, ns3::Ptr< ns3::NetDevice >, ns3::Ptr< ns3::Packet const >, unsigned short, ns3::Address const &, ns3::Address const &, ns3::NetDevice::PacketType, ns3::empty, ns3::empty, ns3::empty >', u'ns3::Node::ProtocolHandler')
    typehandlers.add_type_alias(u'ns3::Callback< void, ns3::Ptr< ns3::NetDevice >, ns3::Ptr< ns3::Packet const >, unsigned short, ns3::Address const &, ns3::Address const &, ns3::NetDevice::PacketType, ns3::empty, ns3::empty, ns3::empty >*', u'ns3::Node::ProtocolHandler*')
    typehandlers.add_type_alias(u'ns3::Callback< void, ns3::Ptr< ns3::NetDevice >, ns3::Ptr< ns3::Packet const >, unsigned short, ns3::Address const &, ns3::Address const &, ns3::NetDevice::PacketType, ns3::empty, ns3::empty, ns3::empty >&', u'ns3::Node::ProtocolHandler&')
    typehandlers.add_type_alias(u'ns3::Callback< void, ns3::Ptr< ns3::NetDevice >, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', u'ns3::Node::DeviceAdditionListener')
    typehandlers.add_type_alias(u'ns3::Callback< void, ns3::Ptr< ns3::NetDevice >, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >*', u'ns3::Node::DeviceAdditionListener*')
    typehandlers.add_type_alias(u'ns3::Callback< void, ns3::Ptr< ns3::NetDevice >, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >&', u'ns3::Node::DeviceAdditionListener&')
    ## random-variable-stream.h (module 'core'): ns3::NormalRandomVariable [class]
    module.add_class('NormalRandomVariable', import_from_module='ns.core', parent=root_module['ns3::RandomVariableStream'])
    ## object-factory.h (module 'core'): ns3::ObjectFactoryChecker [class]
    module.add_class('ObjectFactoryChecker', import_from_module='ns.core', parent=root_module['ns3::AttributeChecker'])
    ## object-factory.h (module 'core'): ns3::ObjectFactoryValue [class]
    module.add_class('ObjectFactoryValue', import_from_module='ns.core', parent=root_module['ns3::AttributeValue'])
    ## output-stream-wrapper.h (module 'network'): ns3::OutputStreamWrapper [class]
    module.add_class('OutputStreamWrapper', import_from_module='ns.network', parent=root_module['ns3::SimpleRefCount< ns3::OutputStreamWrapper, ns3::empty, ns3::DefaultDeleter<ns3::OutputStreamWrapper> >'])
    ## packet.h (module 'network'): ns3::Packet [class]
    module.add_class('Packet', import_from_module='ns.network', parent=root_module['ns3::SimpleRefCount< ns3::Packet, ns3::empty, ns3::DefaultDeleter<ns3::Packet> >'])
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Ptr< ns3::Packet const > )', u'ns3::Packet::TracedCallback')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Ptr< ns3::Packet const > )*', u'ns3::Packet::TracedCallback*')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Ptr< ns3::Packet const > )&', u'ns3::Packet::TracedCallback&')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Ptr< ns3::Packet const >, ns3::Address const & )', u'ns3::Packet::AddressTracedCallback')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Ptr< ns3::Packet const >, ns3::Address const & )*', u'ns3::Packet::AddressTracedCallback*')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Ptr< ns3::Packet const >, ns3::Address const & )&', u'ns3::Packet::AddressTracedCallback&')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Ptr< ns3::Packet const > const, ns3::Address const &, ns3::Address const & )', u'ns3::Packet::TwoAddressTracedCallback')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Ptr< ns3::Packet const > const, ns3::Address const &, ns3::Address const & )*', u'ns3::Packet::TwoAddressTracedCallback*')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Ptr< ns3::Packet const > const, ns3::Address const &, ns3::Address const & )&', u'ns3::Packet::TwoAddressTracedCallback&')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Ptr< ns3::Packet const >, ns3::Mac48Address )', u'ns3::Packet::Mac48AddressTracedCallback')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Ptr< ns3::Packet const >, ns3::Mac48Address )*', u'ns3::Packet::Mac48AddressTracedCallback*')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Ptr< ns3::Packet const >, ns3::Mac48Address )&', u'ns3::Packet::Mac48AddressTracedCallback&')
    typehandlers.add_type_alias(u'void ( * ) ( uint32_t, uint32_t )', u'ns3::Packet::SizeTracedCallback')
    typehandlers.add_type_alias(u'void ( * ) ( uint32_t, uint32_t )*', u'ns3::Packet::SizeTracedCallback*')
    typehandlers.add_type_alias(u'void ( * ) ( uint32_t, uint32_t )&', u'ns3::Packet::SizeTracedCallback&')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Ptr< ns3::Packet const >, double )', u'ns3::Packet::SinrTracedCallback')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Ptr< ns3::Packet const >, double )*', u'ns3::Packet::SinrTracedCallback*')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Ptr< ns3::Packet const >, double )&', u'ns3::Packet::SinrTracedCallback&')
    ## random-variable-stream.h (module 'core'): ns3::ParetoRandomVariable [class]
    module.add_class('ParetoRandomVariable', import_from_module='ns.core', parent=root_module['ns3::RandomVariableStream'])
    ## tcp-l4-protocol.h (module 'internet'): ns3::TcpL4Protocol [class]
    module.add_class('TcpL4Protocol', import_from_module='ns.internet', parent=root_module['ns3::IpL4Protocol'])
    ## nstime.h (module 'core'): ns3::TimeValue [class]
    module.add_class('TimeValue', import_from_module='ns.core', parent=root_module['ns3::AttributeValue'])
    ## type-id.h (module 'core'): ns3::TypeIdChecker [class]
    module.add_class('TypeIdChecker', import_from_module='ns.core', parent=root_module['ns3::AttributeChecker'])
    ## type-id.h (module 'core'): ns3::TypeIdValue [class]
    module.add_class('TypeIdValue', import_from_module='ns.core', parent=root_module['ns3::AttributeValue'])
    ## udp-l4-protocol.h (module 'internet'): ns3::UdpL4Protocol [class]
    module.add_class('UdpL4Protocol', import_from_module='ns.internet', parent=root_module['ns3::IpL4Protocol'])
    ## wifi-mode.h (module 'wifi'): ns3::WifiModeChecker [class]
    module.add_class('WifiModeChecker', import_from_module='ns.wifi', parent=root_module['ns3::AttributeChecker'])
    ## wifi-mode.h (module 'wifi'): ns3::WifiModeValue [class]
    module.add_class('WifiModeValue', import_from_module='ns.wifi', parent=root_module['ns3::AttributeValue'])
    ## address.h (module 'network'): ns3::AddressChecker [class]
    module.add_class('AddressChecker', import_from_module='ns.network', parent=root_module['ns3::AttributeChecker'])
    ## address.h (module 'network'): ns3::AddressValue [class]
    module.add_class('AddressValue', import_from_module='ns.network', parent=root_module['ns3::AttributeValue'])
    ## callback.h (module 'core'): ns3::CallbackImpl<bool, ns3::Ptr<ns3::Socket>, const ns3::Address &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> [class]
    module.add_class('CallbackImpl', import_from_module='ns.core', template_parameters=['bool', 'ns3::Ptr<ns3::Socket>', 'const ns3::Address &', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty'], parent=root_module['ns3::CallbackImplBase'])
    ## callback.h (module 'core'): ns3::CallbackImpl<ns3::ObjectBase *, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> [class]
    module.add_class('CallbackImpl', import_from_module='ns.core', template_parameters=['ns3::ObjectBase *', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty'], parent=root_module['ns3::CallbackImplBase'])
    ## callback.h (module 'core'): ns3::CallbackImpl<void, const ns3::Ipv4Header &, ns3::Ptr<const ns3::Packet>, ns3::Ipv4L3Protocol::DropReason, ns3::Ptr<ns3::Ipv4>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty> [class]
    module.add_class('CallbackImpl', import_from_module='ns.core', template_parameters=['void', 'const ns3::Ipv4Header &', 'ns3::Ptr<const ns3::Packet>', 'ns3::Ipv4L3Protocol::DropReason', 'ns3::Ptr<ns3::Ipv4>', 'unsigned int', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty'], parent=root_module['ns3::CallbackImplBase'])
    ## callback.h (module 'core'): ns3::CallbackImpl<void, const ns3::Ipv4Header &, ns3::Ptr<const ns3::Packet>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> [class]
    module.add_class('CallbackImpl', import_from_module='ns.core', template_parameters=['void', 'const ns3::Ipv4Header &', 'ns3::Ptr<const ns3::Packet>', 'unsigned int', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty'], parent=root_module['ns3::CallbackImplBase'])
    ## callback.h (module 'core'): ns3::CallbackImpl<void, const ns3::WifiMacHeader &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> [class]
    module.add_class('CallbackImpl', import_from_module='ns.core', template_parameters=['void', 'const ns3::WifiMacHeader &', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty'], parent=root_module['ns3::CallbackImplBase'])
    ## callback.h (module 'core'): ns3::CallbackImpl<void, const ns3::rushattackdsr::RushattackdsrOptionSRHeader &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> [class]
    module.add_class('CallbackImpl', import_from_module='ns.core', template_parameters=['void', 'const ns3::rushattackdsr::RushattackdsrOptionSRHeader &', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty'], parent=root_module['ns3::CallbackImplBase'])
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Ipv4Address, unsigned char, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> [class]
    module.add_class('CallbackImpl', import_from_module='ns.core', template_parameters=['void', 'ns3::Ipv4Address', 'unsigned char', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty'], parent=root_module['ns3::CallbackImplBase'])
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Mac48Address, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> [class]
    module.add_class('CallbackImpl', import_from_module='ns.core', template_parameters=['void', 'ns3::Mac48Address', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty'], parent=root_module['ns3::CallbackImplBase'])
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Ptr<const ns3::Packet>, ns3::Ptr<ns3::Ipv4>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> [class]
    module.add_class('CallbackImpl', import_from_module='ns.core', template_parameters=['void', 'ns3::Ptr<const ns3::Packet>', 'ns3::Ptr<ns3::Ipv4>', 'unsigned int', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty'], parent=root_module['ns3::CallbackImplBase'])
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Ptr<const ns3::Packet>, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> [class]
    module.add_class('CallbackImpl', import_from_module='ns.core', template_parameters=['void', 'ns3::Ptr<const ns3::Packet>', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty'], parent=root_module['ns3::CallbackImplBase'])
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Ptr<ns3::NetDevice>, ns3::Ptr<const ns3::Packet>, unsigned short, const ns3::Address &, const ns3::Address &, ns3::NetDevice::PacketType, ns3::empty, ns3::empty, ns3::empty> [class]
    module.add_class('CallbackImpl', import_from_module='ns.core', template_parameters=['void', 'ns3::Ptr<ns3::NetDevice>', 'ns3::Ptr<const ns3::Packet>', 'unsigned short', 'const ns3::Address &', 'const ns3::Address &', 'ns3::NetDevice::PacketType', 'ns3::empty', 'ns3::empty', 'ns3::empty'], parent=root_module['ns3::CallbackImplBase'])
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Ptr<ns3::NetDevice>, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> [class]
    module.add_class('CallbackImpl', import_from_module='ns.core', template_parameters=['void', 'ns3::Ptr<ns3::NetDevice>', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty'], parent=root_module['ns3::CallbackImplBase'])
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Ptr<ns3::Packet>, ns3::Ipv4Address, ns3::Ipv4Address, unsigned char, ns3::Ptr<ns3::Ipv4Route>, ns3::empty, ns3::empty, ns3::empty, ns3::empty> [class]
    module.add_class('CallbackImpl', import_from_module='ns.core', template_parameters=['void', 'ns3::Ptr<ns3::Packet>', 'ns3::Ipv4Address', 'ns3::Ipv4Address', 'unsigned char', 'ns3::Ptr<ns3::Ipv4Route>', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty'], parent=root_module['ns3::CallbackImplBase'])
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Ptr<ns3::Socket>, const ns3::Address &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> [class]
    module.add_class('CallbackImpl', import_from_module='ns.core', template_parameters=['void', 'ns3::Ptr<ns3::Socket>', 'const ns3::Address &', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty'], parent=root_module['ns3::CallbackImplBase'])
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Ptr<ns3::Socket>, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> [class]
    module.add_class('CallbackImpl', import_from_module='ns.core', template_parameters=['void', 'ns3::Ptr<ns3::Socket>', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty'], parent=root_module['ns3::CallbackImplBase'])
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Ptr<ns3::Socket>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> [class]
    module.add_class('CallbackImpl', import_from_module='ns.core', template_parameters=['void', 'ns3::Ptr<ns3::Socket>', 'unsigned int', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty', 'ns3::empty'], parent=root_module['ns3::CallbackImplBase'])
    ## icmpv4-l4-protocol.h (module 'internet'): ns3::Icmpv4L4Protocol [class]
    module.add_class('Icmpv4L4Protocol', import_from_module='ns.internet', parent=root_module['ns3::IpL4Protocol'])
    module.add_container('ns3::WifiModeList', 'ns3::WifiMode', container_type=u'vector')
    module.add_container('std::vector< ns3::Ipv6Address >', 'ns3::Ipv6Address', container_type=u'vector')
    module.add_container('std::list< std::pair< ns3::Ptr< ns3::Packet >, ns3::Ipv4Header > >', 'std::pair< ns3::Ptr< ns3::Packet >, ns3::Ipv4Header >', container_type=u'list')
    module.add_container('std::list< ns3::ArpCache::Entry * >', 'ns3::ArpCache::Entry *', container_type=u'list')
    module.add_container('std::map< unsigned int, unsigned int >', ('unsigned int', 'unsigned int'), container_type=u'map')
    typehandlers.add_type_alias(u'ns3::SequenceNumber< unsigned int, int >', u'ns3::SequenceNumber32')
    typehandlers.add_type_alias(u'ns3::SequenceNumber< unsigned int, int >*', u'ns3::SequenceNumber32*')
    typehandlers.add_type_alias(u'ns3::SequenceNumber< unsigned int, int >&', u'ns3::SequenceNumber32&')
    typehandlers.add_type_alias(u'ns3::SequenceNumber< unsigned short, short >', u'ns3::SequenceNumber16')
    typehandlers.add_type_alias(u'ns3::SequenceNumber< unsigned short, short >*', u'ns3::SequenceNumber16*')
    typehandlers.add_type_alias(u'ns3::SequenceNumber< unsigned short, short >&', u'ns3::SequenceNumber16&')
    typehandlers.add_type_alias(u'ns3::SequenceNumber< unsigned char, signed char >', u'ns3::SequenceNumber8')
    typehandlers.add_type_alias(u'ns3::SequenceNumber< unsigned char, signed char >*', u'ns3::SequenceNumber8*')
    typehandlers.add_type_alias(u'ns3::SequenceNumber< unsigned char, signed char >&', u'ns3::SequenceNumber8&')
    typehandlers.add_type_alias(u'std::vector< ns3::WifiMode >', u'ns3::WifiModeList')
    typehandlers.add_type_alias(u'std::vector< ns3::WifiMode >*', u'ns3::WifiModeList*')
    typehandlers.add_type_alias(u'std::vector< ns3::WifiMode >&', u'ns3::WifiModeList&')
    typehandlers.add_type_alias(u'std::vector< ns3::WifiMode > const_iterator', u'ns3::WifiModeListIterator')
    typehandlers.add_type_alias(u'std::vector< ns3::WifiMode > const_iterator*', u'ns3::WifiModeListIterator*')
    typehandlers.add_type_alias(u'std::vector< ns3::WifiMode > const_iterator&', u'ns3::WifiModeListIterator&')
    
    ## Register a nested module for the namespace FatalImpl
    
    nested_module = module.add_cpp_namespace('FatalImpl')
    register_types_ns3_FatalImpl(nested_module)
    
    
    ## Register a nested module for the namespace Hash
    
    nested_module = module.add_cpp_namespace('Hash')
    register_types_ns3_Hash(nested_module)
    
    
    ## Register a nested module for the namespace TracedValueCallback
    
    nested_module = module.add_cpp_namespace('TracedValueCallback')
    register_types_ns3_TracedValueCallback(nested_module)
    
    
    ## Register a nested module for the namespace rushattackdsr
    
    nested_module = module.add_cpp_namespace('rushattackdsr')
    register_types_ns3_rushattackdsr(nested_module)
    
    
    ## Register a nested module for the namespace tests
    
    nested_module = module.add_cpp_namespace('tests')
    register_types_ns3_tests(nested_module)
    

def register_types_ns3_FatalImpl(module):
    root_module = module.get_root()
    

def register_types_ns3_Hash(module):
    root_module = module.get_root()
    
    ## hash-function.h (module 'core'): ns3::Hash::Implementation [class]
    module.add_class('Implementation', import_from_module='ns.core', parent=root_module['ns3::SimpleRefCount< ns3::Hash::Implementation, ns3::empty, ns3::DefaultDeleter<ns3::Hash::Implementation> >'])
    typehandlers.add_type_alias(u'uint32_t ( * ) ( char const *, std::size_t const )', u'ns3::Hash::Hash32Function_ptr')
    typehandlers.add_type_alias(u'uint32_t ( * ) ( char const *, std::size_t const )*', u'ns3::Hash::Hash32Function_ptr*')
    typehandlers.add_type_alias(u'uint32_t ( * ) ( char const *, std::size_t const )&', u'ns3::Hash::Hash32Function_ptr&')
    typehandlers.add_type_alias(u'uint64_t ( * ) ( char const *, std::size_t const )', u'ns3::Hash::Hash64Function_ptr')
    typehandlers.add_type_alias(u'uint64_t ( * ) ( char const *, std::size_t const )*', u'ns3::Hash::Hash64Function_ptr*')
    typehandlers.add_type_alias(u'uint64_t ( * ) ( char const *, std::size_t const )&', u'ns3::Hash::Hash64Function_ptr&')
    
    ## Register a nested module for the namespace Function
    
    nested_module = module.add_cpp_namespace('Function')
    register_types_ns3_Hash_Function(nested_module)
    

def register_types_ns3_Hash_Function(module):
    root_module = module.get_root()
    
    ## hash-fnv.h (module 'core'): ns3::Hash::Function::Fnv1a [class]
    module.add_class('Fnv1a', import_from_module='ns.core', parent=root_module['ns3::Hash::Implementation'])
    ## hash-function.h (module 'core'): ns3::Hash::Function::Hash32 [class]
    module.add_class('Hash32', import_from_module='ns.core', parent=root_module['ns3::Hash::Implementation'])
    ## hash-function.h (module 'core'): ns3::Hash::Function::Hash64 [class]
    module.add_class('Hash64', import_from_module='ns.core', parent=root_module['ns3::Hash::Implementation'])
    ## hash-murmur3.h (module 'core'): ns3::Hash::Function::Murmur3 [class]
    module.add_class('Murmur3', import_from_module='ns.core', parent=root_module['ns3::Hash::Implementation'])

def register_types_ns3_TracedValueCallback(module):
    root_module = module.get_root()
    
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Time, ns3::Time )', u'ns3::TracedValueCallback::Time')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Time, ns3::Time )*', u'ns3::TracedValueCallback::Time*')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::Time, ns3::Time )&', u'ns3::TracedValueCallback::Time&')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::SequenceNumber32, ns3::SequenceNumber32 )', u'ns3::TracedValueCallback::SequenceNumber32')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::SequenceNumber32, ns3::SequenceNumber32 )*', u'ns3::TracedValueCallback::SequenceNumber32*')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::SequenceNumber32, ns3::SequenceNumber32 )&', u'ns3::TracedValueCallback::SequenceNumber32&')

def register_types_ns3_rushattackdsr(module):
    root_module = module.get_root()
    
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): ns3::rushattackdsr::LinkStates [enumeration]
    module.add_enum('LinkStates', ['PROBABLE', 'QUESTIONABLE'])
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrMessageType [enumeration]
    module.add_enum('RushattackdsrMessageType', ['DSR_CONTROL_PACKET', 'DSR_DATA_PACKET'])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::ErrorType [enumeration]
    module.add_enum('ErrorType', ['NODE_UNREACHABLE', 'FLOW_STATE_NOT_SUPPORTED', 'OPTION_NOT_SUPPORTED'])
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): ns3::rushattackdsr::BlackList [struct]
    module.add_class('BlackList')
    ## rushattackdsr-errorbuff.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrErrorBuffEntry [class]
    module.add_class('RushattackdsrErrorBuffEntry')
    ## rushattackdsr-errorbuff.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrErrorBuffer [class]
    module.add_class('RushattackdsrErrorBuffer')
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrFsHeader [class]
    module.add_class('RushattackdsrFsHeader', parent=root_module['ns3::Header'])
    ## rushattackdsr-gratuitous-reply-table.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrGraReply [class]
    module.add_class('RushattackdsrGraReply', parent=root_module['ns3::Object'])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrLinkStab [class]
    module.add_class('RushattackdsrLinkStab')
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrMaintainBuffEntry [class]
    module.add_class('RushattackdsrMaintainBuffEntry')
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrMaintainBuffer [class]
    module.add_class('RushattackdsrMaintainBuffer')
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrNetworkQueue [class]
    module.add_class('RushattackdsrNetworkQueue', parent=root_module['ns3::Object'])
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrNetworkQueueEntry [class]
    module.add_class('RushattackdsrNetworkQueueEntry')
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrNodeStab [class]
    module.add_class('RushattackdsrNodeStab')
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionField [class]
    module.add_class('RushattackdsrOptionField')
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionHeader [class]
    module.add_class('RushattackdsrOptionHeader', parent=root_module['ns3::Header'])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionHeader::Alignment [struct]
    module.add_class('Alignment', outer_class=root_module['ns3::rushattackdsr::RushattackdsrOptionHeader'])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionPad1Header [class]
    module.add_class('RushattackdsrOptionPad1Header', parent=root_module['ns3::rushattackdsr::RushattackdsrOptionHeader'])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionPadnHeader [class]
    module.add_class('RushattackdsrOptionPadnHeader', parent=root_module['ns3::rushattackdsr::RushattackdsrOptionHeader'])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionRerrHeader [class]
    module.add_class('RushattackdsrOptionRerrHeader', parent=root_module['ns3::rushattackdsr::RushattackdsrOptionHeader'])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionRerrUnreachHeader [class]
    module.add_class('RushattackdsrOptionRerrUnreachHeader', parent=root_module['ns3::rushattackdsr::RushattackdsrOptionRerrHeader'])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionRerrUnsupportHeader [class]
    module.add_class('RushattackdsrOptionRerrUnsupportHeader', parent=root_module['ns3::rushattackdsr::RushattackdsrOptionRerrHeader'])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionRrepHeader [class]
    module.add_class('RushattackdsrOptionRrepHeader', parent=root_module['ns3::rushattackdsr::RushattackdsrOptionHeader'])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionRreqHeader [class]
    module.add_class('RushattackdsrOptionRreqHeader', parent=root_module['ns3::rushattackdsr::RushattackdsrOptionHeader'])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionSRHeader [class]
    module.add_class('RushattackdsrOptionSRHeader', parent=root_module['ns3::rushattackdsr::RushattackdsrOptionHeader'])
    typehandlers.add_type_alias(u'void ( * ) ( ns3::rushattackdsr::RushattackdsrOptionSRHeader const & )', u'ns3::rushattackdsr::RushattackdsrOptionSRHeader::TracedCallback')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::rushattackdsr::RushattackdsrOptionSRHeader const & )*', u'ns3::rushattackdsr::RushattackdsrOptionSRHeader::TracedCallback*')
    typehandlers.add_type_alias(u'void ( * ) ( ns3::rushattackdsr::RushattackdsrOptionSRHeader const & )&', u'ns3::rushattackdsr::RushattackdsrOptionSRHeader::TracedCallback&')
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptions [class]
    module.add_class('RushattackdsrOptions', parent=root_module['ns3::Object'])
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrPassiveBuffEntry [class]
    module.add_class('RushattackdsrPassiveBuffEntry')
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrPassiveBuffer [class]
    module.add_class('RushattackdsrPassiveBuffer', parent=root_module['ns3::Object'])
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrReceivedRreqEntry [class]
    module.add_class('RushattackdsrReceivedRreqEntry')
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRouteCache [class]
    module.add_class('RushattackdsrRouteCache', parent=root_module['ns3::Object'])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRouteCache::Neighbor [struct]
    module.add_class('Neighbor', outer_class=root_module['ns3::rushattackdsr::RushattackdsrRouteCache'])
    typehandlers.add_type_alias(u'std::list< std::vector< ns3::Ipv4Address > >', u'ns3::rushattackdsr::RushattackdsrRouteCache::routeVector')
    typehandlers.add_type_alias(u'std::list< std::vector< ns3::Ipv4Address > >*', u'ns3::rushattackdsr::RushattackdsrRouteCache::routeVector*')
    typehandlers.add_type_alias(u'std::list< std::vector< ns3::Ipv4Address > >&', u'ns3::rushattackdsr::RushattackdsrRouteCache::routeVector&')
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRouteCacheEntry [class]
    module.add_class('RushattackdsrRouteCacheEntry')
    typehandlers.add_type_alias(u'std::vector< ns3::Ipv4Address >', u'ns3::rushattackdsr::RushattackdsrRouteCacheEntry::IP_VECTOR')
    typehandlers.add_type_alias(u'std::vector< ns3::Ipv4Address >*', u'ns3::rushattackdsr::RushattackdsrRouteCacheEntry::IP_VECTOR*')
    typehandlers.add_type_alias(u'std::vector< ns3::Ipv4Address >&', u'ns3::rushattackdsr::RushattackdsrRouteCacheEntry::IP_VECTOR&')
    typehandlers.add_type_alias(u'std::vector< ns3::Ipv4Address > iterator', u'ns3::rushattackdsr::RushattackdsrRouteCacheEntry::Iterator')
    typehandlers.add_type_alias(u'std::vector< ns3::Ipv4Address > iterator*', u'ns3::rushattackdsr::RushattackdsrRouteCacheEntry::Iterator*')
    typehandlers.add_type_alias(u'std::vector< ns3::Ipv4Address > iterator&', u'ns3::rushattackdsr::RushattackdsrRouteCacheEntry::Iterator&')
    ## rushattackdsr-routing.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRouting [class]
    module.add_class('RushattackdsrRouting', parent=root_module['ns3::IpL4Protocol'])
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRoutingHeader [class]
    module.add_class('RushattackdsrRoutingHeader', parent=[root_module['ns3::rushattackdsr::RushattackdsrFsHeader'], root_module['ns3::rushattackdsr::RushattackdsrOptionField']])
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRreqTable [class]
    module.add_class('RushattackdsrRreqTable', parent=root_module['ns3::Object'])
    ## rushattackdsr-rsendbuff.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrSendBuffEntry [class]
    module.add_class('RushattackdsrSendBuffEntry')
    ## rushattackdsr-rsendbuff.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrSendBuffer [class]
    module.add_class('RushattackdsrSendBuffer')
    ## rushattackdsr-gratuitous-reply-table.h (module 'rushattackdsr'): ns3::rushattackdsr::GraReplyEntry [struct]
    module.add_class('GraReplyEntry')
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::Link [struct]
    module.add_class('Link')
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::LinkKey [struct]
    module.add_class('LinkKey')
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::NetworkKey [struct]
    module.add_class('NetworkKey')
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::PassiveKey [struct]
    module.add_class('PassiveKey')
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): ns3::rushattackdsr::RreqTableEntry [struct]
    module.add_class('RreqTableEntry')
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionAck [class]
    module.add_class('RushattackdsrOptionAck', parent=root_module['ns3::rushattackdsr::RushattackdsrOptions'])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionAckHeader [class]
    module.add_class('RushattackdsrOptionAckHeader', parent=root_module['ns3::rushattackdsr::RushattackdsrOptionHeader'])
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionAckReq [class]
    module.add_class('RushattackdsrOptionAckReq', parent=root_module['ns3::rushattackdsr::RushattackdsrOptions'])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionAckReqHeader [class]
    module.add_class('RushattackdsrOptionAckReqHeader', parent=root_module['ns3::rushattackdsr::RushattackdsrOptionHeader'])
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionPad1 [class]
    module.add_class('RushattackdsrOptionPad1', parent=root_module['ns3::rushattackdsr::RushattackdsrOptions'])
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionPadn [class]
    module.add_class('RushattackdsrOptionPadn', parent=root_module['ns3::rushattackdsr::RushattackdsrOptions'])
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionRerr [class]
    module.add_class('RushattackdsrOptionRerr', parent=root_module['ns3::rushattackdsr::RushattackdsrOptions'])
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionRrep [class]
    module.add_class('RushattackdsrOptionRrep', parent=root_module['ns3::rushattackdsr::RushattackdsrOptions'])
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionRreq [class]
    module.add_class('RushattackdsrOptionRreq', parent=root_module['ns3::rushattackdsr::RushattackdsrOptions'])
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionSR [class]
    module.add_class('RushattackdsrOptionSR', parent=root_module['ns3::rushattackdsr::RushattackdsrOptions'])
    module.add_container('std::vector< ns3::rushattackdsr::RushattackdsrErrorBuffEntry >', 'ns3::rushattackdsr::RushattackdsrErrorBuffEntry', container_type=u'vector')
    module.add_container('std::vector< ns3::rushattackdsr::RushattackdsrNetworkQueueEntry >', 'ns3::rushattackdsr::RushattackdsrNetworkQueueEntry', container_type=u'vector')
    module.add_container('std::vector< ns3::Ipv4Address >', 'ns3::Ipv4Address', container_type=u'vector')
    module.add_container('std::list< ns3::rushattackdsr::RushattackdsrRouteCacheEntry >', 'ns3::rushattackdsr::RushattackdsrRouteCacheEntry', container_type=u'list')
    module.add_container('std::list< std::vector< ns3::Ipv4Address > >', 'std::vector< ns3::Ipv4Address >', container_type=u'list')
    module.add_container('ns3::rushattackdsr::RushattackdsrRouteCacheEntry::IP_VECTOR', 'ns3::Ipv4Address', container_type=u'vector')
    module.add_container('std::vector< ns3::rushattackdsr::RushattackdsrRouteCache::Neighbor >', 'ns3::rushattackdsr::RushattackdsrRouteCache::Neighbor', container_type=u'vector')
    module.add_container('std::vector< ns3::Ptr< ns3::ArpCache > >', 'ns3::Ptr< ns3::ArpCache >', container_type=u'vector')
    module.add_container('std::vector< std::string >', 'std::string', container_type=u'vector')
    module.add_container('std::vector< ns3::rushattackdsr::RushattackdsrSendBuffEntry >', 'ns3::rushattackdsr::RushattackdsrSendBuffEntry', container_type=u'vector')

def register_types_ns3_tests(module):
    root_module = module.get_root()
    

def register_methods(root_module):
    register_Ns3Address_methods(root_module, root_module['ns3::Address'])
    register_Ns3AttributeConstructionList_methods(root_module, root_module['ns3::AttributeConstructionList'])
    register_Ns3AttributeConstructionListItem_methods(root_module, root_module['ns3::AttributeConstructionList::Item'])
    register_Ns3Buffer_methods(root_module, root_module['ns3::Buffer'])
    register_Ns3BufferIterator_methods(root_module, root_module['ns3::Buffer::Iterator'])
    register_Ns3ByteTagIterator_methods(root_module, root_module['ns3::ByteTagIterator'])
    register_Ns3ByteTagIteratorItem_methods(root_module, root_module['ns3::ByteTagIterator::Item'])
    register_Ns3ByteTagList_methods(root_module, root_module['ns3::ByteTagList'])
    register_Ns3ByteTagListIterator_methods(root_module, root_module['ns3::ByteTagList::Iterator'])
    register_Ns3ByteTagListIteratorItem_methods(root_module, root_module['ns3::ByteTagList::Iterator::Item'])
    register_Ns3CallbackBase_methods(root_module, root_module['ns3::CallbackBase'])
    register_Ns3DataRate_methods(root_module, root_module['ns3::DataRate'])
    register_Ns3DefaultDeleter__Ns3AttributeAccessor_methods(root_module, root_module['ns3::DefaultDeleter< ns3::AttributeAccessor >'])
    register_Ns3DefaultDeleter__Ns3AttributeChecker_methods(root_module, root_module['ns3::DefaultDeleter< ns3::AttributeChecker >'])
    register_Ns3DefaultDeleter__Ns3AttributeValue_methods(root_module, root_module['ns3::DefaultDeleter< ns3::AttributeValue >'])
    register_Ns3DefaultDeleter__Ns3CallbackImplBase_methods(root_module, root_module['ns3::DefaultDeleter< ns3::CallbackImplBase >'])
    register_Ns3DefaultDeleter__Ns3EventImpl_methods(root_module, root_module['ns3::DefaultDeleter< ns3::EventImpl >'])
    register_Ns3DefaultDeleter__Ns3HashImplementation_methods(root_module, root_module['ns3::DefaultDeleter< ns3::Hash::Implementation >'])
    register_Ns3DefaultDeleter__Ns3Ipv4Route_methods(root_module, root_module['ns3::DefaultDeleter< ns3::Ipv4Route >'])
    register_Ns3DefaultDeleter__Ns3NixVector_methods(root_module, root_module['ns3::DefaultDeleter< ns3::NixVector >'])
    register_Ns3DefaultDeleter__Ns3Packet_methods(root_module, root_module['ns3::DefaultDeleter< ns3::Packet >'])
    register_Ns3DefaultDeleter__Ns3TraceSourceAccessor_methods(root_module, root_module['ns3::DefaultDeleter< ns3::TraceSourceAccessor >'])
    register_Ns3RushattackdsrHelper_methods(root_module, root_module['ns3::RushattackdsrHelper'])
    register_Ns3RushattackdsrMainHelper_methods(root_module, root_module['ns3::RushattackdsrMainHelper'])
    register_Ns3EventGarbageCollector_methods(root_module, root_module['ns3::EventGarbageCollector'])
    register_Ns3EventId_methods(root_module, root_module['ns3::EventId'])
    register_Ns3Hasher_methods(root_module, root_module['ns3::Hasher'])
    register_Ns3Inet6SocketAddress_methods(root_module, root_module['ns3::Inet6SocketAddress'])
    register_Ns3InetSocketAddress_methods(root_module, root_module['ns3::InetSocketAddress'])
    register_Ns3IntToType__0_methods(root_module, root_module['ns3::IntToType< 0 >'])
    register_Ns3IntToType__1_methods(root_module, root_module['ns3::IntToType< 1 >'])
    register_Ns3IntToType__2_methods(root_module, root_module['ns3::IntToType< 2 >'])
    register_Ns3IntToType__3_methods(root_module, root_module['ns3::IntToType< 3 >'])
    register_Ns3IntToType__4_methods(root_module, root_module['ns3::IntToType< 4 >'])
    register_Ns3IntToType__5_methods(root_module, root_module['ns3::IntToType< 5 >'])
    register_Ns3IntToType__6_methods(root_module, root_module['ns3::IntToType< 6 >'])
    register_Ns3Ipv4Address_methods(root_module, root_module['ns3::Ipv4Address'])
    register_Ns3Ipv4InterfaceAddress_methods(root_module, root_module['ns3::Ipv4InterfaceAddress'])
    register_Ns3Ipv4Mask_methods(root_module, root_module['ns3::Ipv4Mask'])
    register_Ns3Ipv6Address_methods(root_module, root_module['ns3::Ipv6Address'])
    register_Ns3Ipv6Prefix_methods(root_module, root_module['ns3::Ipv6Prefix'])
    register_Ns3Mac48Address_methods(root_module, root_module['ns3::Mac48Address'])
    register_Ns3Mac8Address_methods(root_module, root_module['ns3::Mac8Address'])
    register_Ns3NodeContainer_methods(root_module, root_module['ns3::NodeContainer'])
    register_Ns3NonCopyable_methods(root_module, root_module['ns3::NonCopyable'])
    register_Ns3ObjectBase_methods(root_module, root_module['ns3::ObjectBase'])
    register_Ns3ObjectDeleter_methods(root_module, root_module['ns3::ObjectDeleter'])
    register_Ns3ObjectFactory_methods(root_module, root_module['ns3::ObjectFactory'])
    register_Ns3PacketMetadata_methods(root_module, root_module['ns3::PacketMetadata'])
    register_Ns3PacketMetadataItem_methods(root_module, root_module['ns3::PacketMetadata::Item'])
    register_Ns3PacketMetadataItemIterator_methods(root_module, root_module['ns3::PacketMetadata::ItemIterator'])
    register_Ns3PacketTagIterator_methods(root_module, root_module['ns3::PacketTagIterator'])
    register_Ns3PacketTagIteratorItem_methods(root_module, root_module['ns3::PacketTagIterator::Item'])
    register_Ns3PacketTagList_methods(root_module, root_module['ns3::PacketTagList'])
    register_Ns3PacketTagListTagData_methods(root_module, root_module['ns3::PacketTagList::TagData'])
    register_Ns3SimpleRefCount__Ns3Object_Ns3ObjectBase_Ns3ObjectDeleter_methods(root_module, root_module['ns3::SimpleRefCount< ns3::Object, ns3::ObjectBase, ns3::ObjectDeleter >'])
    register_Ns3Simulator_methods(root_module, root_module['ns3::Simulator'])
    register_Ns3SystemWallClockMs_methods(root_module, root_module['ns3::SystemWallClockMs'])
    register_Ns3Tag_methods(root_module, root_module['ns3::Tag'])
    register_Ns3TagBuffer_methods(root_module, root_module['ns3::TagBuffer'])
    register_Ns3TimeWithUnit_methods(root_module, root_module['ns3::TimeWithUnit'])
    register_Ns3Timer_methods(root_module, root_module['ns3::Timer'])
    register_Ns3TimerImpl_methods(root_module, root_module['ns3::TimerImpl'])
    register_Ns3TypeId_methods(root_module, root_module['ns3::TypeId'])
    register_Ns3TypeIdAttributeInformation_methods(root_module, root_module['ns3::TypeId::AttributeInformation'])
    register_Ns3TypeIdTraceSourceInformation_methods(root_module, root_module['ns3::TypeId::TraceSourceInformation'])
    register_Ns3WifiMode_methods(root_module, root_module['ns3::WifiMode'])
    register_Ns3WifiModeFactory_methods(root_module, root_module['ns3::WifiModeFactory'])
    register_Ns3WifiRemoteStation_methods(root_module, root_module['ns3::WifiRemoteStation'])
    register_Ns3WifiRemoteStationInfo_methods(root_module, root_module['ns3::WifiRemoteStationInfo'])
    register_Ns3WifiRemoteStationState_methods(root_module, root_module['ns3::WifiRemoteStationState'])
    register_Ns3Empty_methods(root_module, root_module['ns3::empty'])
    register_Ns3Int64x64_t_methods(root_module, root_module['ns3::int64x64_t'])
    register_Ns3Chunk_methods(root_module, root_module['ns3::Chunk'])
    register_Ns3Header_methods(root_module, root_module['ns3::Header'])
    register_Ns3Icmpv4DestinationUnreachable_methods(root_module, root_module['ns3::Icmpv4DestinationUnreachable'])
    register_Ns3Icmpv4Echo_methods(root_module, root_module['ns3::Icmpv4Echo'])
    register_Ns3Icmpv4Header_methods(root_module, root_module['ns3::Icmpv4Header'])
    register_Ns3Icmpv4TimeExceeded_methods(root_module, root_module['ns3::Icmpv4TimeExceeded'])
    register_Ns3Ipv4Header_methods(root_module, root_module['ns3::Ipv4Header'])
    register_Ns3Ipv6Header_methods(root_module, root_module['ns3::Ipv6Header'])
    register_Ns3Object_methods(root_module, root_module['ns3::Object'])
    register_Ns3ObjectAggregateIterator_methods(root_module, root_module['ns3::Object::AggregateIterator'])
    register_Ns3RandomVariableStream_methods(root_module, root_module['ns3::RandomVariableStream'])
    register_Ns3SequentialRandomVariable_methods(root_module, root_module['ns3::SequentialRandomVariable'])
    register_Ns3SimpleRefCount__Ns3AttributeAccessor_Ns3Empty_Ns3DefaultDeleter__lt__ns3AttributeAccessor__gt___methods(root_module, root_module['ns3::SimpleRefCount< ns3::AttributeAccessor, ns3::empty, ns3::DefaultDeleter<ns3::AttributeAccessor> >'])
    register_Ns3SimpleRefCount__Ns3AttributeChecker_Ns3Empty_Ns3DefaultDeleter__lt__ns3AttributeChecker__gt___methods(root_module, root_module['ns3::SimpleRefCount< ns3::AttributeChecker, ns3::empty, ns3::DefaultDeleter<ns3::AttributeChecker> >'])
    register_Ns3SimpleRefCount__Ns3AttributeValue_Ns3Empty_Ns3DefaultDeleter__lt__ns3AttributeValue__gt___methods(root_module, root_module['ns3::SimpleRefCount< ns3::AttributeValue, ns3::empty, ns3::DefaultDeleter<ns3::AttributeValue> >'])
    register_Ns3SimpleRefCount__Ns3CallbackImplBase_Ns3Empty_Ns3DefaultDeleter__lt__ns3CallbackImplBase__gt___methods(root_module, root_module['ns3::SimpleRefCount< ns3::CallbackImplBase, ns3::empty, ns3::DefaultDeleter<ns3::CallbackImplBase> >'])
    register_Ns3SimpleRefCount__Ns3EventImpl_Ns3Empty_Ns3DefaultDeleter__lt__ns3EventImpl__gt___methods(root_module, root_module['ns3::SimpleRefCount< ns3::EventImpl, ns3::empty, ns3::DefaultDeleter<ns3::EventImpl> >'])
    register_Ns3SimpleRefCount__Ns3HashImplementation_Ns3Empty_Ns3DefaultDeleter__lt__ns3HashImplementation__gt___methods(root_module, root_module['ns3::SimpleRefCount< ns3::Hash::Implementation, ns3::empty, ns3::DefaultDeleter<ns3::Hash::Implementation> >'])
    register_Ns3SimpleRefCount__Ns3Ipv4MulticastRoute_Ns3Empty_Ns3DefaultDeleter__lt__ns3Ipv4MulticastRoute__gt___methods(root_module, root_module['ns3::SimpleRefCount< ns3::Ipv4MulticastRoute, ns3::empty, ns3::DefaultDeleter<ns3::Ipv4MulticastRoute> >'])
    register_Ns3SimpleRefCount__Ns3Ipv4Route_Ns3Empty_Ns3DefaultDeleter__lt__ns3Ipv4Route__gt___methods(root_module, root_module['ns3::SimpleRefCount< ns3::Ipv4Route, ns3::empty, ns3::DefaultDeleter<ns3::Ipv4Route> >'])
    register_Ns3SimpleRefCount__Ns3NixVector_Ns3Empty_Ns3DefaultDeleter__lt__ns3NixVector__gt___methods(root_module, root_module['ns3::SimpleRefCount< ns3::NixVector, ns3::empty, ns3::DefaultDeleter<ns3::NixVector> >'])
    register_Ns3SimpleRefCount__Ns3OutputStreamWrapper_Ns3Empty_Ns3DefaultDeleter__lt__ns3OutputStreamWrapper__gt___methods(root_module, root_module['ns3::SimpleRefCount< ns3::OutputStreamWrapper, ns3::empty, ns3::DefaultDeleter<ns3::OutputStreamWrapper> >'])
    register_Ns3SimpleRefCount__Ns3Packet_Ns3Empty_Ns3DefaultDeleter__lt__ns3Packet__gt___methods(root_module, root_module['ns3::SimpleRefCount< ns3::Packet, ns3::empty, ns3::DefaultDeleter<ns3::Packet> >'])
    register_Ns3SimpleRefCount__Ns3TraceSourceAccessor_Ns3Empty_Ns3DefaultDeleter__lt__ns3TraceSourceAccessor__gt___methods(root_module, root_module['ns3::SimpleRefCount< ns3::TraceSourceAccessor, ns3::empty, ns3::DefaultDeleter<ns3::TraceSourceAccessor> >'])
    register_Ns3Socket_methods(root_module, root_module['ns3::Socket'])
    register_Ns3SocketIpTosTag_methods(root_module, root_module['ns3::SocketIpTosTag'])
    register_Ns3SocketIpTtlTag_methods(root_module, root_module['ns3::SocketIpTtlTag'])
    register_Ns3SocketIpv6HopLimitTag_methods(root_module, root_module['ns3::SocketIpv6HopLimitTag'])
    register_Ns3SocketIpv6TclassTag_methods(root_module, root_module['ns3::SocketIpv6TclassTag'])
    register_Ns3SocketPriorityTag_methods(root_module, root_module['ns3::SocketPriorityTag'])
    register_Ns3SocketSetDontFragmentTag_methods(root_module, root_module['ns3::SocketSetDontFragmentTag'])
    register_Ns3Time_methods(root_module, root_module['ns3::Time'])
    register_Ns3TraceSourceAccessor_methods(root_module, root_module['ns3::TraceSourceAccessor'])
    register_Ns3Trailer_methods(root_module, root_module['ns3::Trailer'])
    register_Ns3TriangularRandomVariable_methods(root_module, root_module['ns3::TriangularRandomVariable'])
    register_Ns3UniformRandomVariable_methods(root_module, root_module['ns3::UniformRandomVariable'])
    register_Ns3WeibullRandomVariable_methods(root_module, root_module['ns3::WeibullRandomVariable'])
    register_Ns3WifiMac_methods(root_module, root_module['ns3::WifiMac'])
    register_Ns3WifiRemoteStationManager_methods(root_module, root_module['ns3::WifiRemoteStationManager'])
    register_Ns3ZetaRandomVariable_methods(root_module, root_module['ns3::ZetaRandomVariable'])
    register_Ns3ZipfRandomVariable_methods(root_module, root_module['ns3::ZipfRandomVariable'])
    register_Ns3ArpCache_methods(root_module, root_module['ns3::ArpCache'])
    register_Ns3ArpCacheEntry_methods(root_module, root_module['ns3::ArpCache::Entry'])
    register_Ns3AttributeAccessor_methods(root_module, root_module['ns3::AttributeAccessor'])
    register_Ns3AttributeChecker_methods(root_module, root_module['ns3::AttributeChecker'])
    register_Ns3AttributeValue_methods(root_module, root_module['ns3::AttributeValue'])
    register_Ns3CallbackChecker_methods(root_module, root_module['ns3::CallbackChecker'])
    register_Ns3CallbackImplBase_methods(root_module, root_module['ns3::CallbackImplBase'])
    register_Ns3CallbackValue_methods(root_module, root_module['ns3::CallbackValue'])
    register_Ns3ConstantRandomVariable_methods(root_module, root_module['ns3::ConstantRandomVariable'])
    register_Ns3DataRateChecker_methods(root_module, root_module['ns3::DataRateChecker'])
    register_Ns3DataRateValue_methods(root_module, root_module['ns3::DataRateValue'])
    register_Ns3DeterministicRandomVariable_methods(root_module, root_module['ns3::DeterministicRandomVariable'])
    register_Ns3EmpiricalRandomVariable_methods(root_module, root_module['ns3::EmpiricalRandomVariable'])
    register_Ns3EmptyAttributeAccessor_methods(root_module, root_module['ns3::EmptyAttributeAccessor'])
    register_Ns3EmptyAttributeChecker_methods(root_module, root_module['ns3::EmptyAttributeChecker'])
    register_Ns3EmptyAttributeValue_methods(root_module, root_module['ns3::EmptyAttributeValue'])
    register_Ns3EnumChecker_methods(root_module, root_module['ns3::EnumChecker'])
    register_Ns3EnumValue_methods(root_module, root_module['ns3::EnumValue'])
    register_Ns3ErlangRandomVariable_methods(root_module, root_module['ns3::ErlangRandomVariable'])
    register_Ns3EventImpl_methods(root_module, root_module['ns3::EventImpl'])
    register_Ns3ExponentialRandomVariable_methods(root_module, root_module['ns3::ExponentialRandomVariable'])
    register_Ns3GammaRandomVariable_methods(root_module, root_module['ns3::GammaRandomVariable'])
    register_Ns3IpL4Protocol_methods(root_module, root_module['ns3::IpL4Protocol'])
    register_Ns3Ipv4_methods(root_module, root_module['ns3::Ipv4'])
    register_Ns3Ipv4AddressChecker_methods(root_module, root_module['ns3::Ipv4AddressChecker'])
    register_Ns3Ipv4AddressValue_methods(root_module, root_module['ns3::Ipv4AddressValue'])
    register_Ns3Ipv4Interface_methods(root_module, root_module['ns3::Ipv4Interface'])
    register_Ns3Ipv4L3Protocol_methods(root_module, root_module['ns3::Ipv4L3Protocol'])
    register_Ns3Ipv4MaskChecker_methods(root_module, root_module['ns3::Ipv4MaskChecker'])
    register_Ns3Ipv4MaskValue_methods(root_module, root_module['ns3::Ipv4MaskValue'])
    register_Ns3Ipv4MulticastRoute_methods(root_module, root_module['ns3::Ipv4MulticastRoute'])
    register_Ns3Ipv4Route_methods(root_module, root_module['ns3::Ipv4Route'])
    register_Ns3Ipv4RoutingProtocol_methods(root_module, root_module['ns3::Ipv4RoutingProtocol'])
    register_Ns3Ipv6AddressChecker_methods(root_module, root_module['ns3::Ipv6AddressChecker'])
    register_Ns3Ipv6AddressValue_methods(root_module, root_module['ns3::Ipv6AddressValue'])
    register_Ns3Ipv6PrefixChecker_methods(root_module, root_module['ns3::Ipv6PrefixChecker'])
    register_Ns3Ipv6PrefixValue_methods(root_module, root_module['ns3::Ipv6PrefixValue'])
    register_Ns3LogNormalRandomVariable_methods(root_module, root_module['ns3::LogNormalRandomVariable'])
    register_Ns3Mac48AddressChecker_methods(root_module, root_module['ns3::Mac48AddressChecker'])
    register_Ns3Mac48AddressValue_methods(root_module, root_module['ns3::Mac48AddressValue'])
    register_Ns3NetDevice_methods(root_module, root_module['ns3::NetDevice'])
    register_Ns3NixVector_methods(root_module, root_module['ns3::NixVector'])
    register_Ns3Node_methods(root_module, root_module['ns3::Node'])
    register_Ns3NormalRandomVariable_methods(root_module, root_module['ns3::NormalRandomVariable'])
    register_Ns3ObjectFactoryChecker_methods(root_module, root_module['ns3::ObjectFactoryChecker'])
    register_Ns3ObjectFactoryValue_methods(root_module, root_module['ns3::ObjectFactoryValue'])
    register_Ns3OutputStreamWrapper_methods(root_module, root_module['ns3::OutputStreamWrapper'])
    register_Ns3Packet_methods(root_module, root_module['ns3::Packet'])
    register_Ns3ParetoRandomVariable_methods(root_module, root_module['ns3::ParetoRandomVariable'])
    register_Ns3TcpL4Protocol_methods(root_module, root_module['ns3::TcpL4Protocol'])
    register_Ns3TimeValue_methods(root_module, root_module['ns3::TimeValue'])
    register_Ns3TypeIdChecker_methods(root_module, root_module['ns3::TypeIdChecker'])
    register_Ns3TypeIdValue_methods(root_module, root_module['ns3::TypeIdValue'])
    register_Ns3UdpL4Protocol_methods(root_module, root_module['ns3::UdpL4Protocol'])
    register_Ns3WifiModeChecker_methods(root_module, root_module['ns3::WifiModeChecker'])
    register_Ns3WifiModeValue_methods(root_module, root_module['ns3::WifiModeValue'])
    register_Ns3AddressChecker_methods(root_module, root_module['ns3::AddressChecker'])
    register_Ns3AddressValue_methods(root_module, root_module['ns3::AddressValue'])
    register_Ns3CallbackImpl__Bool_Ns3Ptr__lt__ns3Socket__gt___Const_ns3Address___amp___Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, root_module['ns3::CallbackImpl< bool, ns3::Ptr<ns3::Socket>, const ns3::Address &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >'])
    register_Ns3CallbackImpl__Ns3ObjectBase___star___Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, root_module['ns3::CallbackImpl< ns3::ObjectBase *, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >'])
    register_Ns3CallbackImpl__Void_Const_ns3Ipv4Header___amp___Ns3Ptr__lt__const_ns3Packet__gt___Ns3Ipv4L3ProtocolDropReason_Ns3Ptr__lt__ns3Ipv4__gt___Unsigned_int_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, root_module['ns3::CallbackImpl< void, const ns3::Ipv4Header &, ns3::Ptr<const ns3::Packet>, ns3::Ipv4L3Protocol::DropReason, ns3::Ptr<ns3::Ipv4>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty >'])
    register_Ns3CallbackImpl__Void_Const_ns3Ipv4Header___amp___Ns3Ptr__lt__const_ns3Packet__gt___Unsigned_int_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, root_module['ns3::CallbackImpl< void, const ns3::Ipv4Header &, ns3::Ptr<const ns3::Packet>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >'])
    register_Ns3CallbackImpl__Void_Const_ns3WifiMacHeader___amp___Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, root_module['ns3::CallbackImpl< void, const ns3::WifiMacHeader &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >'])
    register_Ns3CallbackImpl__Void_Const_ns3RushattackdsrRushattackdsrOptionSRHeader___amp___Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, root_module['ns3::CallbackImpl< void, const ns3::rushattackdsr::RushattackdsrOptionSRHeader &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >'])
    register_Ns3CallbackImpl__Void_Ns3Ipv4Address_Unsigned_char_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, root_module['ns3::CallbackImpl< void, ns3::Ipv4Address, unsigned char, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >'])
    register_Ns3CallbackImpl__Void_Ns3Mac48Address_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, root_module['ns3::CallbackImpl< void, ns3::Mac48Address, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >'])
    register_Ns3CallbackImpl__Void_Ns3Ptr__lt__const_ns3Packet__gt___Ns3Ptr__lt__ns3Ipv4__gt___Unsigned_int_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, root_module['ns3::CallbackImpl< void, ns3::Ptr<const ns3::Packet>, ns3::Ptr<ns3::Ipv4>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >'])
    register_Ns3CallbackImpl__Void_Ns3Ptr__lt__const_ns3Packet__gt___Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, root_module['ns3::CallbackImpl< void, ns3::Ptr<const ns3::Packet>, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >'])
    register_Ns3CallbackImpl__Void_Ns3Ptr__lt__ns3NetDevice__gt___Ns3Ptr__lt__const_ns3Packet__gt___Unsigned_short_Const_ns3Address___amp___Const_ns3Address___amp___Ns3NetDevicePacketType_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, root_module['ns3::CallbackImpl< void, ns3::Ptr<ns3::NetDevice>, ns3::Ptr<const ns3::Packet>, unsigned short, const ns3::Address &, const ns3::Address &, ns3::NetDevice::PacketType, ns3::empty, ns3::empty, ns3::empty >'])
    register_Ns3CallbackImpl__Void_Ns3Ptr__lt__ns3NetDevice__gt___Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, root_module['ns3::CallbackImpl< void, ns3::Ptr<ns3::NetDevice>, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >'])
    register_Ns3CallbackImpl__Void_Ns3Ptr__lt__ns3Packet__gt___Ns3Ipv4Address_Ns3Ipv4Address_Unsigned_char_Ns3Ptr__lt__ns3Ipv4Route__gt___Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, root_module['ns3::CallbackImpl< void, ns3::Ptr<ns3::Packet>, ns3::Ipv4Address, ns3::Ipv4Address, unsigned char, ns3::Ptr<ns3::Ipv4Route>, ns3::empty, ns3::empty, ns3::empty, ns3::empty >'])
    register_Ns3CallbackImpl__Void_Ns3Ptr__lt__ns3Socket__gt___Const_ns3Address___amp___Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, root_module['ns3::CallbackImpl< void, ns3::Ptr<ns3::Socket>, const ns3::Address &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >'])
    register_Ns3CallbackImpl__Void_Ns3Ptr__lt__ns3Socket__gt___Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, root_module['ns3::CallbackImpl< void, ns3::Ptr<ns3::Socket>, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >'])
    register_Ns3CallbackImpl__Void_Ns3Ptr__lt__ns3Socket__gt___Unsigned_int_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, root_module['ns3::CallbackImpl< void, ns3::Ptr<ns3::Socket>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >'])
    register_Ns3Icmpv4L4Protocol_methods(root_module, root_module['ns3::Icmpv4L4Protocol'])
    register_Ns3HashImplementation_methods(root_module, root_module['ns3::Hash::Implementation'])
    register_Ns3HashFunctionFnv1a_methods(root_module, root_module['ns3::Hash::Function::Fnv1a'])
    register_Ns3HashFunctionHash32_methods(root_module, root_module['ns3::Hash::Function::Hash32'])
    register_Ns3HashFunctionHash64_methods(root_module, root_module['ns3::Hash::Function::Hash64'])
    register_Ns3HashFunctionMurmur3_methods(root_module, root_module['ns3::Hash::Function::Murmur3'])
    register_Ns3RushattackdsrBlackList_methods(root_module, root_module['ns3::rushattackdsr::BlackList'])
    register_Ns3RushattackdsrRushattackdsrErrorBuffEntry_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrErrorBuffEntry'])
    register_Ns3RushattackdsrRushattackdsrErrorBuffer_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrErrorBuffer'])
    register_Ns3RushattackdsrRushattackdsrFsHeader_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrFsHeader'])
    register_Ns3RushattackdsrRushattackdsrGraReply_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrGraReply'])
    register_Ns3RushattackdsrRushattackdsrLinkStab_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrLinkStab'])
    register_Ns3RushattackdsrRushattackdsrMaintainBuffEntry_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrMaintainBuffEntry'])
    register_Ns3RushattackdsrRushattackdsrMaintainBuffer_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrMaintainBuffer'])
    register_Ns3RushattackdsrRushattackdsrNetworkQueue_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrNetworkQueue'])
    register_Ns3RushattackdsrRushattackdsrNetworkQueueEntry_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrNetworkQueueEntry'])
    register_Ns3RushattackdsrRushattackdsrNodeStab_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrNodeStab'])
    register_Ns3RushattackdsrRushattackdsrOptionField_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrOptionField'])
    register_Ns3RushattackdsrRushattackdsrOptionHeader_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrOptionHeader'])
    register_Ns3RushattackdsrRushattackdsrOptionHeaderAlignment_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrOptionHeader::Alignment'])
    register_Ns3RushattackdsrRushattackdsrOptionPad1Header_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrOptionPad1Header'])
    register_Ns3RushattackdsrRushattackdsrOptionPadnHeader_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrOptionPadnHeader'])
    register_Ns3RushattackdsrRushattackdsrOptionRerrHeader_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrOptionRerrHeader'])
    register_Ns3RushattackdsrRushattackdsrOptionRerrUnreachHeader_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrOptionRerrUnreachHeader'])
    register_Ns3RushattackdsrRushattackdsrOptionRerrUnsupportHeader_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrOptionRerrUnsupportHeader'])
    register_Ns3RushattackdsrRushattackdsrOptionRrepHeader_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrOptionRrepHeader'])
    register_Ns3RushattackdsrRushattackdsrOptionRreqHeader_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrOptionRreqHeader'])
    register_Ns3RushattackdsrRushattackdsrOptionSRHeader_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrOptionSRHeader'])
    register_Ns3RushattackdsrRushattackdsrOptions_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrOptions'])
    register_Ns3RushattackdsrRushattackdsrPassiveBuffEntry_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrPassiveBuffEntry'])
    register_Ns3RushattackdsrRushattackdsrPassiveBuffer_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrPassiveBuffer'])
    register_Ns3RushattackdsrRushattackdsrReceivedRreqEntry_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrReceivedRreqEntry'])
    register_Ns3RushattackdsrRushattackdsrRouteCache_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrRouteCache'])
    register_Ns3RushattackdsrRushattackdsrRouteCacheNeighbor_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrRouteCache::Neighbor'])
    register_Ns3RushattackdsrRushattackdsrRouteCacheEntry_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrRouteCacheEntry'])
    register_Ns3RushattackdsrRushattackdsrRouting_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrRouting'])
    register_Ns3RushattackdsrRushattackdsrRoutingHeader_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrRoutingHeader'])
    register_Ns3RushattackdsrRushattackdsrRreqTable_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrRreqTable'])
    register_Ns3RushattackdsrRushattackdsrSendBuffEntry_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrSendBuffEntry'])
    register_Ns3RushattackdsrRushattackdsrSendBuffer_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrSendBuffer'])
    register_Ns3RushattackdsrGraReplyEntry_methods(root_module, root_module['ns3::rushattackdsr::GraReplyEntry'])
    register_Ns3RushattackdsrLink_methods(root_module, root_module['ns3::rushattackdsr::Link'])
    register_Ns3RushattackdsrLinkKey_methods(root_module, root_module['ns3::rushattackdsr::LinkKey'])
    register_Ns3RushattackdsrNetworkKey_methods(root_module, root_module['ns3::rushattackdsr::NetworkKey'])
    register_Ns3RushattackdsrPassiveKey_methods(root_module, root_module['ns3::rushattackdsr::PassiveKey'])
    register_Ns3RushattackdsrRreqTableEntry_methods(root_module, root_module['ns3::rushattackdsr::RreqTableEntry'])
    register_Ns3RushattackdsrRushattackdsrOptionAck_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrOptionAck'])
    register_Ns3RushattackdsrRushattackdsrOptionAckHeader_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrOptionAckHeader'])
    register_Ns3RushattackdsrRushattackdsrOptionAckReq_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrOptionAckReq'])
    register_Ns3RushattackdsrRushattackdsrOptionAckReqHeader_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrOptionAckReqHeader'])
    register_Ns3RushattackdsrRushattackdsrOptionPad1_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrOptionPad1'])
    register_Ns3RushattackdsrRushattackdsrOptionPadn_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrOptionPadn'])
    register_Ns3RushattackdsrRushattackdsrOptionRerr_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrOptionRerr'])
    register_Ns3RushattackdsrRushattackdsrOptionRrep_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrOptionRrep'])
    register_Ns3RushattackdsrRushattackdsrOptionRreq_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrOptionRreq'])
    register_Ns3RushattackdsrRushattackdsrOptionSR_methods(root_module, root_module['ns3::rushattackdsr::RushattackdsrOptionSR'])
    return

def register_Ns3Address_methods(root_module, cls):
    cls.add_binary_comparison_operator('==')
    cls.add_binary_comparison_operator('!=')
    cls.add_binary_comparison_operator('<')
    cls.add_output_stream_operator()
    ## address.h (module 'network'): ns3::Address::Address() [constructor]
    cls.add_constructor([])
    ## address.h (module 'network'): ns3::Address::Address(uint8_t type, uint8_t const * buffer, uint8_t len) [constructor]
    cls.add_constructor([param('uint8_t', 'type'), param('uint8_t const *', 'buffer'), param('uint8_t', 'len')])
    ## address.h (module 'network'): ns3::Address::Address(ns3::Address const & address) [constructor]
    cls.add_constructor([param('ns3::Address const &', 'address')])
    ## address.h (module 'network'): bool ns3::Address::CheckCompatible(uint8_t type, uint8_t len) const [member function]
    cls.add_method('CheckCompatible', 
                   'bool', 
                   [param('uint8_t', 'type'), param('uint8_t', 'len')], 
                   is_const=True)
    ## address.h (module 'network'): uint32_t ns3::Address::CopyAllFrom(uint8_t const * buffer, uint8_t len) [member function]
    cls.add_method('CopyAllFrom', 
                   'uint32_t', 
                   [param('uint8_t const *', 'buffer'), param('uint8_t', 'len')])
    ## address.h (module 'network'): uint32_t ns3::Address::CopyAllTo(uint8_t * buffer, uint8_t len) const [member function]
    cls.add_method('CopyAllTo', 
                   'uint32_t', 
                   [param('uint8_t *', 'buffer'), param('uint8_t', 'len')], 
                   is_const=True)
    ## address.h (module 'network'): uint32_t ns3::Address::CopyFrom(uint8_t const * buffer, uint8_t len) [member function]
    cls.add_method('CopyFrom', 
                   'uint32_t', 
                   [param('uint8_t const *', 'buffer'), param('uint8_t', 'len')])
    ## address.h (module 'network'): uint32_t ns3::Address::CopyTo(uint8_t * buffer) const [member function]
    cls.add_method('CopyTo', 
                   'uint32_t', 
                   [param('uint8_t *', 'buffer')], 
                   is_const=True)
    ## address.h (module 'network'): void ns3::Address::Deserialize(ns3::TagBuffer buffer) [member function]
    cls.add_method('Deserialize', 
                   'void', 
                   [param('ns3::TagBuffer', 'buffer')])
    ## address.h (module 'network'): uint8_t ns3::Address::GetLength() const [member function]
    cls.add_method('GetLength', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## address.h (module 'network'): uint32_t ns3::Address::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## address.h (module 'network'): bool ns3::Address::IsInvalid() const [member function]
    cls.add_method('IsInvalid', 
                   'bool', 
                   [], 
                   is_const=True)
    ## address.h (module 'network'): bool ns3::Address::IsMatchingType(uint8_t type) const [member function]
    cls.add_method('IsMatchingType', 
                   'bool', 
                   [param('uint8_t', 'type')], 
                   is_const=True)
    ## address.h (module 'network'): static uint8_t ns3::Address::Register() [member function]
    cls.add_method('Register', 
                   'uint8_t', 
                   [], 
                   is_static=True)
    ## address.h (module 'network'): void ns3::Address::Serialize(ns3::TagBuffer buffer) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::TagBuffer', 'buffer')], 
                   is_const=True)
    return

def register_Ns3AttributeConstructionList_methods(root_module, cls):
    ## attribute-construction-list.h (module 'core'): ns3::AttributeConstructionList::AttributeConstructionList(ns3::AttributeConstructionList const & arg0) [constructor]
    cls.add_constructor([param('ns3::AttributeConstructionList const &', 'arg0')])
    ## attribute-construction-list.h (module 'core'): ns3::AttributeConstructionList::AttributeConstructionList() [constructor]
    cls.add_constructor([])
    ## attribute-construction-list.h (module 'core'): void ns3::AttributeConstructionList::Add(std::string name, ns3::Ptr<const ns3::AttributeChecker> checker, ns3::Ptr<ns3::AttributeValue> value) [member function]
    cls.add_method('Add', 
                   'void', 
                   [param('std::string', 'name'), param('ns3::Ptr< ns3::AttributeChecker const >', 'checker'), param('ns3::Ptr< ns3::AttributeValue >', 'value')])
    ## attribute-construction-list.h (module 'core'): ns3::AttributeConstructionList::CIterator ns3::AttributeConstructionList::Begin() const [member function]
    cls.add_method('Begin', 
                   'ns3::AttributeConstructionList::CIterator', 
                   [], 
                   is_const=True)
    ## attribute-construction-list.h (module 'core'): ns3::AttributeConstructionList::CIterator ns3::AttributeConstructionList::End() const [member function]
    cls.add_method('End', 
                   'ns3::AttributeConstructionList::CIterator', 
                   [], 
                   is_const=True)
    ## attribute-construction-list.h (module 'core'): ns3::Ptr<ns3::AttributeValue> ns3::AttributeConstructionList::Find(ns3::Ptr<const ns3::AttributeChecker> checker) const [member function]
    cls.add_method('Find', 
                   'ns3::Ptr< ns3::AttributeValue >', 
                   [param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_const=True)
    return

def register_Ns3AttributeConstructionListItem_methods(root_module, cls):
    ## attribute-construction-list.h (module 'core'): ns3::AttributeConstructionList::Item::Item() [constructor]
    cls.add_constructor([])
    ## attribute-construction-list.h (module 'core'): ns3::AttributeConstructionList::Item::Item(ns3::AttributeConstructionList::Item const & arg0) [constructor]
    cls.add_constructor([param('ns3::AttributeConstructionList::Item const &', 'arg0')])
    ## attribute-construction-list.h (module 'core'): ns3::AttributeConstructionList::Item::checker [variable]
    cls.add_instance_attribute('checker', 'ns3::Ptr< ns3::AttributeChecker const >', is_const=False)
    ## attribute-construction-list.h (module 'core'): ns3::AttributeConstructionList::Item::name [variable]
    cls.add_instance_attribute('name', 'std::string', is_const=False)
    ## attribute-construction-list.h (module 'core'): ns3::AttributeConstructionList::Item::value [variable]
    cls.add_instance_attribute('value', 'ns3::Ptr< ns3::AttributeValue >', is_const=False)
    return

def register_Ns3Buffer_methods(root_module, cls):
    ## buffer.h (module 'network'): ns3::Buffer::Buffer(ns3::Buffer const & o) [constructor]
    cls.add_constructor([param('ns3::Buffer const &', 'o')])
    ## buffer.h (module 'network'): ns3::Buffer::Buffer() [constructor]
    cls.add_constructor([])
    ## buffer.h (module 'network'): ns3::Buffer::Buffer(uint32_t dataSize) [constructor]
    cls.add_constructor([param('uint32_t', 'dataSize')])
    ## buffer.h (module 'network'): ns3::Buffer::Buffer(uint32_t dataSize, bool initialize) [constructor]
    cls.add_constructor([param('uint32_t', 'dataSize'), param('bool', 'initialize')])
    ## buffer.h (module 'network'): void ns3::Buffer::AddAtEnd(uint32_t end) [member function]
    cls.add_method('AddAtEnd', 
                   'void', 
                   [param('uint32_t', 'end')])
    ## buffer.h (module 'network'): void ns3::Buffer::AddAtEnd(ns3::Buffer const & o) [member function]
    cls.add_method('AddAtEnd', 
                   'void', 
                   [param('ns3::Buffer const &', 'o')])
    ## buffer.h (module 'network'): void ns3::Buffer::AddAtStart(uint32_t start) [member function]
    cls.add_method('AddAtStart', 
                   'void', 
                   [param('uint32_t', 'start')])
    ## buffer.h (module 'network'): ns3::Buffer::Iterator ns3::Buffer::Begin() const [member function]
    cls.add_method('Begin', 
                   'ns3::Buffer::Iterator', 
                   [], 
                   is_const=True)
    ## buffer.h (module 'network'): void ns3::Buffer::CopyData(std::ostream * os, uint32_t size) const [member function]
    cls.add_method('CopyData', 
                   'void', 
                   [param('std::ostream *', 'os'), param('uint32_t', 'size')], 
                   is_const=True)
    ## buffer.h (module 'network'): uint32_t ns3::Buffer::CopyData(uint8_t * buffer, uint32_t size) const [member function]
    cls.add_method('CopyData', 
                   'uint32_t', 
                   [param('uint8_t *', 'buffer'), param('uint32_t', 'size')], 
                   is_const=True)
    ## buffer.h (module 'network'): ns3::Buffer ns3::Buffer::CreateFragment(uint32_t start, uint32_t length) const [member function]
    cls.add_method('CreateFragment', 
                   'ns3::Buffer', 
                   [param('uint32_t', 'start'), param('uint32_t', 'length')], 
                   is_const=True)
    ## buffer.h (module 'network'): uint32_t ns3::Buffer::Deserialize(uint8_t const * buffer, uint32_t size) [member function]
    cls.add_method('Deserialize', 
                   'uint32_t', 
                   [param('uint8_t const *', 'buffer'), param('uint32_t', 'size')])
    ## buffer.h (module 'network'): ns3::Buffer::Iterator ns3::Buffer::End() const [member function]
    cls.add_method('End', 
                   'ns3::Buffer::Iterator', 
                   [], 
                   is_const=True)
    ## buffer.h (module 'network'): uint32_t ns3::Buffer::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## buffer.h (module 'network'): uint32_t ns3::Buffer::GetSize() const [member function]
    cls.add_method('GetSize', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## buffer.h (module 'network'): uint8_t const * ns3::Buffer::PeekData() const [member function]
    cls.add_method('PeekData', 
                   'uint8_t const *', 
                   [], 
                   is_const=True)
    ## buffer.h (module 'network'): void ns3::Buffer::RemoveAtEnd(uint32_t end) [member function]
    cls.add_method('RemoveAtEnd', 
                   'void', 
                   [param('uint32_t', 'end')])
    ## buffer.h (module 'network'): void ns3::Buffer::RemoveAtStart(uint32_t start) [member function]
    cls.add_method('RemoveAtStart', 
                   'void', 
                   [param('uint32_t', 'start')])
    ## buffer.h (module 'network'): uint32_t ns3::Buffer::Serialize(uint8_t * buffer, uint32_t maxSize) const [member function]
    cls.add_method('Serialize', 
                   'uint32_t', 
                   [param('uint8_t *', 'buffer'), param('uint32_t', 'maxSize')], 
                   is_const=True)
    return

def register_Ns3BufferIterator_methods(root_module, cls):
    ## buffer.h (module 'network'): ns3::Buffer::Iterator::Iterator(ns3::Buffer::Iterator const & arg0) [constructor]
    cls.add_constructor([param('ns3::Buffer::Iterator const &', 'arg0')])
    ## buffer.h (module 'network'): ns3::Buffer::Iterator::Iterator() [constructor]
    cls.add_constructor([])
    ## buffer.h (module 'network'): uint16_t ns3::Buffer::Iterator::CalculateIpChecksum(uint16_t size) [member function]
    cls.add_method('CalculateIpChecksum', 
                   'uint16_t', 
                   [param('uint16_t', 'size')])
    ## buffer.h (module 'network'): uint16_t ns3::Buffer::Iterator::CalculateIpChecksum(uint16_t size, uint32_t initialChecksum) [member function]
    cls.add_method('CalculateIpChecksum', 
                   'uint16_t', 
                   [param('uint16_t', 'size'), param('uint32_t', 'initialChecksum')])
    ## buffer.h (module 'network'): uint32_t ns3::Buffer::Iterator::GetDistanceFrom(ns3::Buffer::Iterator const & o) const [member function]
    cls.add_method('GetDistanceFrom', 
                   'uint32_t', 
                   [param('ns3::Buffer::Iterator const &', 'o')], 
                   is_const=True)
    ## buffer.h (module 'network'): uint32_t ns3::Buffer::Iterator::GetRemainingSize() const [member function]
    cls.add_method('GetRemainingSize', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## buffer.h (module 'network'): uint32_t ns3::Buffer::Iterator::GetSize() const [member function]
    cls.add_method('GetSize', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## buffer.h (module 'network'): bool ns3::Buffer::Iterator::IsEnd() const [member function]
    cls.add_method('IsEnd', 
                   'bool', 
                   [], 
                   is_const=True)
    ## buffer.h (module 'network'): bool ns3::Buffer::Iterator::IsStart() const [member function]
    cls.add_method('IsStart', 
                   'bool', 
                   [], 
                   is_const=True)
    ## buffer.h (module 'network'): void ns3::Buffer::Iterator::Next() [member function]
    cls.add_method('Next', 
                   'void', 
                   [])
    ## buffer.h (module 'network'): void ns3::Buffer::Iterator::Next(uint32_t delta) [member function]
    cls.add_method('Next', 
                   'void', 
                   [param('uint32_t', 'delta')])
    ## buffer.h (module 'network'): uint8_t ns3::Buffer::Iterator::PeekU8() [member function]
    cls.add_method('PeekU8', 
                   'uint8_t', 
                   [])
    ## buffer.h (module 'network'): void ns3::Buffer::Iterator::Prev() [member function]
    cls.add_method('Prev', 
                   'void', 
                   [])
    ## buffer.h (module 'network'): void ns3::Buffer::Iterator::Prev(uint32_t delta) [member function]
    cls.add_method('Prev', 
                   'void', 
                   [param('uint32_t', 'delta')])
    ## buffer.h (module 'network'): void ns3::Buffer::Iterator::Read(uint8_t * buffer, uint32_t size) [member function]
    cls.add_method('Read', 
                   'void', 
                   [param('uint8_t *', 'buffer'), param('uint32_t', 'size')])
    ## buffer.h (module 'network'): void ns3::Buffer::Iterator::Read(ns3::Buffer::Iterator start, uint32_t size) [member function]
    cls.add_method('Read', 
                   'void', 
                   [param('ns3::Buffer::Iterator', 'start'), param('uint32_t', 'size')])
    ## buffer.h (module 'network'): uint16_t ns3::Buffer::Iterator::ReadLsbtohU16() [member function]
    cls.add_method('ReadLsbtohU16', 
                   'uint16_t', 
                   [])
    ## buffer.h (module 'network'): uint32_t ns3::Buffer::Iterator::ReadLsbtohU32() [member function]
    cls.add_method('ReadLsbtohU32', 
                   'uint32_t', 
                   [])
    ## buffer.h (module 'network'): uint64_t ns3::Buffer::Iterator::ReadLsbtohU64() [member function]
    cls.add_method('ReadLsbtohU64', 
                   'uint64_t', 
                   [])
    ## buffer.h (module 'network'): uint16_t ns3::Buffer::Iterator::ReadNtohU16() [member function]
    cls.add_method('ReadNtohU16', 
                   'uint16_t', 
                   [])
    ## buffer.h (module 'network'): uint32_t ns3::Buffer::Iterator::ReadNtohU32() [member function]
    cls.add_method('ReadNtohU32', 
                   'uint32_t', 
                   [])
    ## buffer.h (module 'network'): uint64_t ns3::Buffer::Iterator::ReadNtohU64() [member function]
    cls.add_method('ReadNtohU64', 
                   'uint64_t', 
                   [])
    ## buffer.h (module 'network'): uint16_t ns3::Buffer::Iterator::ReadU16() [member function]
    cls.add_method('ReadU16', 
                   'uint16_t', 
                   [])
    ## buffer.h (module 'network'): uint32_t ns3::Buffer::Iterator::ReadU32() [member function]
    cls.add_method('ReadU32', 
                   'uint32_t', 
                   [])
    ## buffer.h (module 'network'): uint64_t ns3::Buffer::Iterator::ReadU64() [member function]
    cls.add_method('ReadU64', 
                   'uint64_t', 
                   [])
    ## buffer.h (module 'network'): uint8_t ns3::Buffer::Iterator::ReadU8() [member function]
    cls.add_method('ReadU8', 
                   'uint8_t', 
                   [])
    ## buffer.h (module 'network'): void ns3::Buffer::Iterator::Write(uint8_t const * buffer, uint32_t size) [member function]
    cls.add_method('Write', 
                   'void', 
                   [param('uint8_t const *', 'buffer'), param('uint32_t', 'size')])
    ## buffer.h (module 'network'): void ns3::Buffer::Iterator::Write(ns3::Buffer::Iterator start, ns3::Buffer::Iterator end) [member function]
    cls.add_method('Write', 
                   'void', 
                   [param('ns3::Buffer::Iterator', 'start'), param('ns3::Buffer::Iterator', 'end')])
    ## buffer.h (module 'network'): void ns3::Buffer::Iterator::WriteHtolsbU16(uint16_t data) [member function]
    cls.add_method('WriteHtolsbU16', 
                   'void', 
                   [param('uint16_t', 'data')])
    ## buffer.h (module 'network'): void ns3::Buffer::Iterator::WriteHtolsbU32(uint32_t data) [member function]
    cls.add_method('WriteHtolsbU32', 
                   'void', 
                   [param('uint32_t', 'data')])
    ## buffer.h (module 'network'): void ns3::Buffer::Iterator::WriteHtolsbU64(uint64_t data) [member function]
    cls.add_method('WriteHtolsbU64', 
                   'void', 
                   [param('uint64_t', 'data')])
    ## buffer.h (module 'network'): void ns3::Buffer::Iterator::WriteHtonU16(uint16_t data) [member function]
    cls.add_method('WriteHtonU16', 
                   'void', 
                   [param('uint16_t', 'data')])
    ## buffer.h (module 'network'): void ns3::Buffer::Iterator::WriteHtonU32(uint32_t data) [member function]
    cls.add_method('WriteHtonU32', 
                   'void', 
                   [param('uint32_t', 'data')])
    ## buffer.h (module 'network'): void ns3::Buffer::Iterator::WriteHtonU64(uint64_t data) [member function]
    cls.add_method('WriteHtonU64', 
                   'void', 
                   [param('uint64_t', 'data')])
    ## buffer.h (module 'network'): void ns3::Buffer::Iterator::WriteU16(uint16_t data) [member function]
    cls.add_method('WriteU16', 
                   'void', 
                   [param('uint16_t', 'data')])
    ## buffer.h (module 'network'): void ns3::Buffer::Iterator::WriteU32(uint32_t data) [member function]
    cls.add_method('WriteU32', 
                   'void', 
                   [param('uint32_t', 'data')])
    ## buffer.h (module 'network'): void ns3::Buffer::Iterator::WriteU64(uint64_t data) [member function]
    cls.add_method('WriteU64', 
                   'void', 
                   [param('uint64_t', 'data')])
    ## buffer.h (module 'network'): void ns3::Buffer::Iterator::WriteU8(uint8_t data) [member function]
    cls.add_method('WriteU8', 
                   'void', 
                   [param('uint8_t', 'data')])
    ## buffer.h (module 'network'): void ns3::Buffer::Iterator::WriteU8(uint8_t data, uint32_t len) [member function]
    cls.add_method('WriteU8', 
                   'void', 
                   [param('uint8_t', 'data'), param('uint32_t', 'len')])
    return

def register_Ns3ByteTagIterator_methods(root_module, cls):
    ## packet.h (module 'network'): ns3::ByteTagIterator::ByteTagIterator(ns3::ByteTagIterator const & arg0) [constructor]
    cls.add_constructor([param('ns3::ByteTagIterator const &', 'arg0')])
    ## packet.h (module 'network'): bool ns3::ByteTagIterator::HasNext() const [member function]
    cls.add_method('HasNext', 
                   'bool', 
                   [], 
                   is_const=True)
    ## packet.h (module 'network'): ns3::ByteTagIterator::Item ns3::ByteTagIterator::Next() [member function]
    cls.add_method('Next', 
                   'ns3::ByteTagIterator::Item', 
                   [])
    return

def register_Ns3ByteTagIteratorItem_methods(root_module, cls):
    ## packet.h (module 'network'): ns3::ByteTagIterator::Item::Item(ns3::ByteTagIterator::Item const & arg0) [constructor]
    cls.add_constructor([param('ns3::ByteTagIterator::Item const &', 'arg0')])
    ## packet.h (module 'network'): uint32_t ns3::ByteTagIterator::Item::GetEnd() const [member function]
    cls.add_method('GetEnd', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## packet.h (module 'network'): uint32_t ns3::ByteTagIterator::Item::GetStart() const [member function]
    cls.add_method('GetStart', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## packet.h (module 'network'): void ns3::ByteTagIterator::Item::GetTag(ns3::Tag & tag) const [member function]
    cls.add_method('GetTag', 
                   'void', 
                   [param('ns3::Tag &', 'tag')], 
                   is_const=True)
    ## packet.h (module 'network'): ns3::TypeId ns3::ByteTagIterator::Item::GetTypeId() const [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True)
    return

def register_Ns3ByteTagList_methods(root_module, cls):
    ## byte-tag-list.h (module 'network'): ns3::ByteTagList::ByteTagList() [constructor]
    cls.add_constructor([])
    ## byte-tag-list.h (module 'network'): ns3::ByteTagList::ByteTagList(ns3::ByteTagList const & o) [constructor]
    cls.add_constructor([param('ns3::ByteTagList const &', 'o')])
    ## byte-tag-list.h (module 'network'): ns3::TagBuffer ns3::ByteTagList::Add(ns3::TypeId tid, uint32_t bufferSize, int32_t start, int32_t end) [member function]
    cls.add_method('Add', 
                   'ns3::TagBuffer', 
                   [param('ns3::TypeId', 'tid'), param('uint32_t', 'bufferSize'), param('int32_t', 'start'), param('int32_t', 'end')])
    ## byte-tag-list.h (module 'network'): void ns3::ByteTagList::Add(ns3::ByteTagList const & o) [member function]
    cls.add_method('Add', 
                   'void', 
                   [param('ns3::ByteTagList const &', 'o')])
    ## byte-tag-list.h (module 'network'): void ns3::ByteTagList::AddAtEnd(int32_t appendOffset) [member function]
    cls.add_method('AddAtEnd', 
                   'void', 
                   [param('int32_t', 'appendOffset')])
    ## byte-tag-list.h (module 'network'): void ns3::ByteTagList::AddAtStart(int32_t prependOffset) [member function]
    cls.add_method('AddAtStart', 
                   'void', 
                   [param('int32_t', 'prependOffset')])
    ## byte-tag-list.h (module 'network'): void ns3::ByteTagList::Adjust(int32_t adjustment) [member function]
    cls.add_method('Adjust', 
                   'void', 
                   [param('int32_t', 'adjustment')])
    ## byte-tag-list.h (module 'network'): ns3::ByteTagList::Iterator ns3::ByteTagList::Begin(int32_t offsetStart, int32_t offsetEnd) const [member function]
    cls.add_method('Begin', 
                   'ns3::ByteTagList::Iterator', 
                   [param('int32_t', 'offsetStart'), param('int32_t', 'offsetEnd')], 
                   is_const=True)
    ## byte-tag-list.h (module 'network'): void ns3::ByteTagList::RemoveAll() [member function]
    cls.add_method('RemoveAll', 
                   'void', 
                   [])
    return

def register_Ns3ByteTagListIterator_methods(root_module, cls):
    ## byte-tag-list.h (module 'network'): ns3::ByteTagList::Iterator::Iterator(ns3::ByteTagList::Iterator const & arg0) [constructor]
    cls.add_constructor([param('ns3::ByteTagList::Iterator const &', 'arg0')])
    ## byte-tag-list.h (module 'network'): uint32_t ns3::ByteTagList::Iterator::GetOffsetStart() const [member function]
    cls.add_method('GetOffsetStart', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## byte-tag-list.h (module 'network'): bool ns3::ByteTagList::Iterator::HasNext() const [member function]
    cls.add_method('HasNext', 
                   'bool', 
                   [], 
                   is_const=True)
    ## byte-tag-list.h (module 'network'): ns3::ByteTagList::Iterator::Item ns3::ByteTagList::Iterator::Next() [member function]
    cls.add_method('Next', 
                   'ns3::ByteTagList::Iterator::Item', 
                   [])
    return

def register_Ns3ByteTagListIteratorItem_methods(root_module, cls):
    ## byte-tag-list.h (module 'network'): ns3::ByteTagList::Iterator::Item::Item(ns3::ByteTagList::Iterator::Item const & arg0) [constructor]
    cls.add_constructor([param('ns3::ByteTagList::Iterator::Item const &', 'arg0')])
    ## byte-tag-list.h (module 'network'): ns3::ByteTagList::Iterator::Item::Item(ns3::TagBuffer buf) [constructor]
    cls.add_constructor([param('ns3::TagBuffer', 'buf')])
    ## byte-tag-list.h (module 'network'): ns3::ByteTagList::Iterator::Item::buf [variable]
    cls.add_instance_attribute('buf', 'ns3::TagBuffer', is_const=False)
    ## byte-tag-list.h (module 'network'): ns3::ByteTagList::Iterator::Item::end [variable]
    cls.add_instance_attribute('end', 'int32_t', is_const=False)
    ## byte-tag-list.h (module 'network'): ns3::ByteTagList::Iterator::Item::size [variable]
    cls.add_instance_attribute('size', 'uint32_t', is_const=False)
    ## byte-tag-list.h (module 'network'): ns3::ByteTagList::Iterator::Item::start [variable]
    cls.add_instance_attribute('start', 'int32_t', is_const=False)
    ## byte-tag-list.h (module 'network'): ns3::ByteTagList::Iterator::Item::tid [variable]
    cls.add_instance_attribute('tid', 'ns3::TypeId', is_const=False)
    return

def register_Ns3CallbackBase_methods(root_module, cls):
    ## callback.h (module 'core'): ns3::CallbackBase::CallbackBase(ns3::CallbackBase const & arg0) [constructor]
    cls.add_constructor([param('ns3::CallbackBase const &', 'arg0')])
    ## callback.h (module 'core'): ns3::CallbackBase::CallbackBase() [constructor]
    cls.add_constructor([])
    ## callback.h (module 'core'): ns3::Ptr<ns3::CallbackImplBase> ns3::CallbackBase::GetImpl() const [member function]
    cls.add_method('GetImpl', 
                   'ns3::Ptr< ns3::CallbackImplBase >', 
                   [], 
                   is_const=True)
    ## callback.h (module 'core'): ns3::CallbackBase::CallbackBase(ns3::Ptr<ns3::CallbackImplBase> impl) [constructor]
    cls.add_constructor([param('ns3::Ptr< ns3::CallbackImplBase >', 'impl')], 
                        visibility='protected')
    return

def register_Ns3DataRate_methods(root_module, cls):
    cls.add_output_stream_operator()
    cls.add_binary_comparison_operator('!=')
    cls.add_binary_comparison_operator('<')
    cls.add_binary_comparison_operator('<=')
    cls.add_binary_comparison_operator('==')
    cls.add_binary_comparison_operator('>')
    cls.add_binary_comparison_operator('>=')
    ## data-rate.h (module 'network'): ns3::DataRate::DataRate(ns3::DataRate const & arg0) [constructor]
    cls.add_constructor([param('ns3::DataRate const &', 'arg0')])
    ## data-rate.h (module 'network'): ns3::DataRate::DataRate() [constructor]
    cls.add_constructor([])
    ## data-rate.h (module 'network'): ns3::DataRate::DataRate(uint64_t bps) [constructor]
    cls.add_constructor([param('uint64_t', 'bps')])
    ## data-rate.h (module 'network'): ns3::DataRate::DataRate(std::string rate) [constructor]
    cls.add_constructor([param('std::string', 'rate')])
    ## data-rate.h (module 'network'): ns3::Time ns3::DataRate::CalculateBitsTxTime(uint32_t bits) const [member function]
    cls.add_method('CalculateBitsTxTime', 
                   'ns3::Time', 
                   [param('uint32_t', 'bits')], 
                   is_const=True)
    ## data-rate.h (module 'network'): ns3::Time ns3::DataRate::CalculateBytesTxTime(uint32_t bytes) const [member function]
    cls.add_method('CalculateBytesTxTime', 
                   'ns3::Time', 
                   [param('uint32_t', 'bytes')], 
                   is_const=True)
    ## data-rate.h (module 'network'): double ns3::DataRate::CalculateTxTime(uint32_t bytes) const [member function]
    cls.add_method('CalculateTxTime', 
                   'double', 
                   [param('uint32_t', 'bytes')], 
                   deprecated=True, is_const=True)
    ## data-rate.h (module 'network'): uint64_t ns3::DataRate::GetBitRate() const [member function]
    cls.add_method('GetBitRate', 
                   'uint64_t', 
                   [], 
                   is_const=True)
    return

def register_Ns3DefaultDeleter__Ns3AttributeAccessor_methods(root_module, cls):
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::AttributeAccessor>::DefaultDeleter() [constructor]
    cls.add_constructor([])
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::AttributeAccessor>::DefaultDeleter(ns3::DefaultDeleter<ns3::AttributeAccessor> const & arg0) [constructor]
    cls.add_constructor([param('ns3::DefaultDeleter< ns3::AttributeAccessor > const &', 'arg0')])
    ## default-deleter.h (module 'core'): static void ns3::DefaultDeleter<ns3::AttributeAccessor>::Delete(ns3::AttributeAccessor * object) [member function]
    cls.add_method('Delete', 
                   'void', 
                   [param('ns3::AttributeAccessor *', 'object')], 
                   is_static=True)
    return

def register_Ns3DefaultDeleter__Ns3AttributeChecker_methods(root_module, cls):
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::AttributeChecker>::DefaultDeleter() [constructor]
    cls.add_constructor([])
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::AttributeChecker>::DefaultDeleter(ns3::DefaultDeleter<ns3::AttributeChecker> const & arg0) [constructor]
    cls.add_constructor([param('ns3::DefaultDeleter< ns3::AttributeChecker > const &', 'arg0')])
    ## default-deleter.h (module 'core'): static void ns3::DefaultDeleter<ns3::AttributeChecker>::Delete(ns3::AttributeChecker * object) [member function]
    cls.add_method('Delete', 
                   'void', 
                   [param('ns3::AttributeChecker *', 'object')], 
                   is_static=True)
    return

def register_Ns3DefaultDeleter__Ns3AttributeValue_methods(root_module, cls):
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::AttributeValue>::DefaultDeleter() [constructor]
    cls.add_constructor([])
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::AttributeValue>::DefaultDeleter(ns3::DefaultDeleter<ns3::AttributeValue> const & arg0) [constructor]
    cls.add_constructor([param('ns3::DefaultDeleter< ns3::AttributeValue > const &', 'arg0')])
    ## default-deleter.h (module 'core'): static void ns3::DefaultDeleter<ns3::AttributeValue>::Delete(ns3::AttributeValue * object) [member function]
    cls.add_method('Delete', 
                   'void', 
                   [param('ns3::AttributeValue *', 'object')], 
                   is_static=True)
    return

def register_Ns3DefaultDeleter__Ns3CallbackImplBase_methods(root_module, cls):
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::CallbackImplBase>::DefaultDeleter() [constructor]
    cls.add_constructor([])
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::CallbackImplBase>::DefaultDeleter(ns3::DefaultDeleter<ns3::CallbackImplBase> const & arg0) [constructor]
    cls.add_constructor([param('ns3::DefaultDeleter< ns3::CallbackImplBase > const &', 'arg0')])
    ## default-deleter.h (module 'core'): static void ns3::DefaultDeleter<ns3::CallbackImplBase>::Delete(ns3::CallbackImplBase * object) [member function]
    cls.add_method('Delete', 
                   'void', 
                   [param('ns3::CallbackImplBase *', 'object')], 
                   is_static=True)
    return

def register_Ns3DefaultDeleter__Ns3EventImpl_methods(root_module, cls):
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::EventImpl>::DefaultDeleter() [constructor]
    cls.add_constructor([])
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::EventImpl>::DefaultDeleter(ns3::DefaultDeleter<ns3::EventImpl> const & arg0) [constructor]
    cls.add_constructor([param('ns3::DefaultDeleter< ns3::EventImpl > const &', 'arg0')])
    ## default-deleter.h (module 'core'): static void ns3::DefaultDeleter<ns3::EventImpl>::Delete(ns3::EventImpl * object) [member function]
    cls.add_method('Delete', 
                   'void', 
                   [param('ns3::EventImpl *', 'object')], 
                   is_static=True)
    return

def register_Ns3DefaultDeleter__Ns3HashImplementation_methods(root_module, cls):
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::Hash::Implementation>::DefaultDeleter() [constructor]
    cls.add_constructor([])
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::Hash::Implementation>::DefaultDeleter(ns3::DefaultDeleter<ns3::Hash::Implementation> const & arg0) [constructor]
    cls.add_constructor([param('ns3::DefaultDeleter< ns3::Hash::Implementation > const &', 'arg0')])
    ## default-deleter.h (module 'core'): static void ns3::DefaultDeleter<ns3::Hash::Implementation>::Delete(ns3::Hash::Implementation * object) [member function]
    cls.add_method('Delete', 
                   'void', 
                   [param('ns3::Hash::Implementation *', 'object')], 
                   is_static=True)
    return

def register_Ns3DefaultDeleter__Ns3Ipv4Route_methods(root_module, cls):
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::Ipv4Route>::DefaultDeleter() [constructor]
    cls.add_constructor([])
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::Ipv4Route>::DefaultDeleter(ns3::DefaultDeleter<ns3::Ipv4Route> const & arg0) [constructor]
    cls.add_constructor([param('ns3::DefaultDeleter< ns3::Ipv4Route > const &', 'arg0')])
    ## default-deleter.h (module 'core'): static void ns3::DefaultDeleter<ns3::Ipv4Route>::Delete(ns3::Ipv4Route * object) [member function]
    cls.add_method('Delete', 
                   'void', 
                   [param('ns3::Ipv4Route *', 'object')], 
                   is_static=True)
    return

def register_Ns3DefaultDeleter__Ns3NixVector_methods(root_module, cls):
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::NixVector>::DefaultDeleter() [constructor]
    cls.add_constructor([])
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::NixVector>::DefaultDeleter(ns3::DefaultDeleter<ns3::NixVector> const & arg0) [constructor]
    cls.add_constructor([param('ns3::DefaultDeleter< ns3::NixVector > const &', 'arg0')])
    ## default-deleter.h (module 'core'): static void ns3::DefaultDeleter<ns3::NixVector>::Delete(ns3::NixVector * object) [member function]
    cls.add_method('Delete', 
                   'void', 
                   [param('ns3::NixVector *', 'object')], 
                   is_static=True)
    return

def register_Ns3DefaultDeleter__Ns3Packet_methods(root_module, cls):
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::Packet>::DefaultDeleter() [constructor]
    cls.add_constructor([])
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::Packet>::DefaultDeleter(ns3::DefaultDeleter<ns3::Packet> const & arg0) [constructor]
    cls.add_constructor([param('ns3::DefaultDeleter< ns3::Packet > const &', 'arg0')])
    ## default-deleter.h (module 'core'): static void ns3::DefaultDeleter<ns3::Packet>::Delete(ns3::Packet * object) [member function]
    cls.add_method('Delete', 
                   'void', 
                   [param('ns3::Packet *', 'object')], 
                   is_static=True)
    return

def register_Ns3DefaultDeleter__Ns3TraceSourceAccessor_methods(root_module, cls):
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::TraceSourceAccessor>::DefaultDeleter() [constructor]
    cls.add_constructor([])
    ## default-deleter.h (module 'core'): ns3::DefaultDeleter<ns3::TraceSourceAccessor>::DefaultDeleter(ns3::DefaultDeleter<ns3::TraceSourceAccessor> const & arg0) [constructor]
    cls.add_constructor([param('ns3::DefaultDeleter< ns3::TraceSourceAccessor > const &', 'arg0')])
    ## default-deleter.h (module 'core'): static void ns3::DefaultDeleter<ns3::TraceSourceAccessor>::Delete(ns3::TraceSourceAccessor * object) [member function]
    cls.add_method('Delete', 
                   'void', 
                   [param('ns3::TraceSourceAccessor *', 'object')], 
                   is_static=True)
    return

def register_Ns3RushattackdsrHelper_methods(root_module, cls):
    ## rushattackdsr-helper.h (module 'rushattackdsr'): ns3::RushattackdsrHelper::RushattackdsrHelper() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-helper.h (module 'rushattackdsr'): ns3::RushattackdsrHelper::RushattackdsrHelper(ns3::RushattackdsrHelper const & arg0) [constructor]
    cls.add_constructor([param('ns3::RushattackdsrHelper const &', 'arg0')])
    ## rushattackdsr-helper.h (module 'rushattackdsr'): ns3::RushattackdsrHelper * ns3::RushattackdsrHelper::Copy() const [member function]
    cls.add_method('Copy', 
                   'ns3::RushattackdsrHelper *', 
                   [], 
                   is_const=True)
    ## rushattackdsr-helper.h (module 'rushattackdsr'): ns3::Ptr<ns3::rushattackdsr::RushattackdsrRouting> ns3::RushattackdsrHelper::Create(ns3::Ptr<ns3::Node> node) const [member function]
    cls.add_method('Create', 
                   'ns3::Ptr< ns3::rushattackdsr::RushattackdsrRouting >', 
                   [param('ns3::Ptr< ns3::Node >', 'node')], 
                   is_const=True)
    ## rushattackdsr-helper.h (module 'rushattackdsr'): void ns3::RushattackdsrHelper::Set(std::string name, ns3::AttributeValue const & value) [member function]
    cls.add_method('Set', 
                   'void', 
                   [param('std::string', 'name'), param('ns3::AttributeValue const &', 'value')])
    return

def register_Ns3RushattackdsrMainHelper_methods(root_module, cls):
    ## rushattackdsr-main-helper.h (module 'rushattackdsr'): ns3::RushattackdsrMainHelper::RushattackdsrMainHelper() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-main-helper.h (module 'rushattackdsr'): ns3::RushattackdsrMainHelper::RushattackdsrMainHelper(ns3::RushattackdsrMainHelper const & arg0) [constructor]
    cls.add_constructor([param('ns3::RushattackdsrMainHelper const &', 'arg0')])
    ## rushattackdsr-main-helper.h (module 'rushattackdsr'): void ns3::RushattackdsrMainHelper::Install(ns3::RushattackdsrHelper & rushattackdsrHelper, ns3::NodeContainer nodes) [member function]
    cls.add_method('Install', 
                   'void', 
                   [param('ns3::RushattackdsrHelper &', 'rushattackdsrHelper'), param('ns3::NodeContainer', 'nodes')])
    ## rushattackdsr-main-helper.h (module 'rushattackdsr'): void ns3::RushattackdsrMainHelper::SetRushattackdsrHelper(ns3::RushattackdsrHelper & rushattackdsrHelper) [member function]
    cls.add_method('SetRushattackdsrHelper', 
                   'void', 
                   [param('ns3::RushattackdsrHelper &', 'rushattackdsrHelper')])
    return

def register_Ns3EventGarbageCollector_methods(root_module, cls):
    ## event-garbage-collector.h (module 'core'): ns3::EventGarbageCollector::EventGarbageCollector() [constructor]
    cls.add_constructor([])
    ## event-garbage-collector.h (module 'core'): void ns3::EventGarbageCollector::Track(ns3::EventId event) [member function]
    cls.add_method('Track', 
                   'void', 
                   [param('ns3::EventId', 'event')])
    ## event-garbage-collector.h (module 'core'): ns3::EventGarbageCollector::EventGarbageCollector(ns3::EventGarbageCollector const & arg0) [constructor]
    cls.add_constructor([param('ns3::EventGarbageCollector const &', 'arg0')])
    return

def register_Ns3EventId_methods(root_module, cls):
    cls.add_binary_comparison_operator('==')
    cls.add_binary_comparison_operator('!=')
    cls.add_binary_comparison_operator('<')
    ## event-id.h (module 'core'): ns3::EventId::EventId(ns3::EventId const & arg0) [constructor]
    cls.add_constructor([param('ns3::EventId const &', 'arg0')])
    ## event-id.h (module 'core'): ns3::EventId::EventId() [constructor]
    cls.add_constructor([])
    ## event-id.h (module 'core'): ns3::EventId::EventId(ns3::Ptr<ns3::EventImpl> const & impl, uint64_t ts, uint32_t context, uint32_t uid) [constructor]
    cls.add_constructor([param('ns3::Ptr< ns3::EventImpl > const &', 'impl'), param('uint64_t', 'ts'), param('uint32_t', 'context'), param('uint32_t', 'uid')])
    ## event-id.h (module 'core'): void ns3::EventId::Cancel() [member function]
    cls.add_method('Cancel', 
                   'void', 
                   [])
    ## event-id.h (module 'core'): uint32_t ns3::EventId::GetContext() const [member function]
    cls.add_method('GetContext', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## event-id.h (module 'core'): uint64_t ns3::EventId::GetTs() const [member function]
    cls.add_method('GetTs', 
                   'uint64_t', 
                   [], 
                   is_const=True)
    ## event-id.h (module 'core'): uint32_t ns3::EventId::GetUid() const [member function]
    cls.add_method('GetUid', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## event-id.h (module 'core'): bool ns3::EventId::IsExpired() const [member function]
    cls.add_method('IsExpired', 
                   'bool', 
                   [], 
                   is_const=True)
    ## event-id.h (module 'core'): bool ns3::EventId::IsRunning() const [member function]
    cls.add_method('IsRunning', 
                   'bool', 
                   [], 
                   is_const=True)
    ## event-id.h (module 'core'): ns3::EventImpl * ns3::EventId::PeekEventImpl() const [member function]
    cls.add_method('PeekEventImpl', 
                   'ns3::EventImpl *', 
                   [], 
                   is_const=True)
    return

def register_Ns3Hasher_methods(root_module, cls):
    ## hash.h (module 'core'): ns3::Hasher::Hasher(ns3::Hasher const & arg0) [constructor]
    cls.add_constructor([param('ns3::Hasher const &', 'arg0')])
    ## hash.h (module 'core'): ns3::Hasher::Hasher() [constructor]
    cls.add_constructor([])
    ## hash.h (module 'core'): ns3::Hasher::Hasher(ns3::Ptr<ns3::Hash::Implementation> hp) [constructor]
    cls.add_constructor([param('ns3::Ptr< ns3::Hash::Implementation >', 'hp')])
    ## hash.h (module 'core'): uint32_t ns3::Hasher::GetHash32(char const * buffer, std::size_t const size) [member function]
    cls.add_method('GetHash32', 
                   'uint32_t', 
                   [param('char const *', 'buffer'), param('std::size_t const', 'size')])
    ## hash.h (module 'core'): uint32_t ns3::Hasher::GetHash32(std::string const s) [member function]
    cls.add_method('GetHash32', 
                   'uint32_t', 
                   [param('std::string const', 's')])
    ## hash.h (module 'core'): uint64_t ns3::Hasher::GetHash64(char const * buffer, std::size_t const size) [member function]
    cls.add_method('GetHash64', 
                   'uint64_t', 
                   [param('char const *', 'buffer'), param('std::size_t const', 'size')])
    ## hash.h (module 'core'): uint64_t ns3::Hasher::GetHash64(std::string const s) [member function]
    cls.add_method('GetHash64', 
                   'uint64_t', 
                   [param('std::string const', 's')])
    ## hash.h (module 'core'): ns3::Hasher & ns3::Hasher::clear() [member function]
    cls.add_method('clear', 
                   'ns3::Hasher &', 
                   [])
    return

def register_Ns3Inet6SocketAddress_methods(root_module, cls):
    ## inet6-socket-address.h (module 'network'): ns3::Inet6SocketAddress::Inet6SocketAddress(ns3::Inet6SocketAddress const & arg0) [constructor]
    cls.add_constructor([param('ns3::Inet6SocketAddress const &', 'arg0')])
    ## inet6-socket-address.h (module 'network'): ns3::Inet6SocketAddress::Inet6SocketAddress(ns3::Ipv6Address ipv6, uint16_t port) [constructor]
    cls.add_constructor([param('ns3::Ipv6Address', 'ipv6'), param('uint16_t', 'port')])
    ## inet6-socket-address.h (module 'network'): ns3::Inet6SocketAddress::Inet6SocketAddress(ns3::Ipv6Address ipv6) [constructor]
    cls.add_constructor([param('ns3::Ipv6Address', 'ipv6')])
    ## inet6-socket-address.h (module 'network'): ns3::Inet6SocketAddress::Inet6SocketAddress(uint16_t port) [constructor]
    cls.add_constructor([param('uint16_t', 'port')])
    ## inet6-socket-address.h (module 'network'): ns3::Inet6SocketAddress::Inet6SocketAddress(char const * ipv6, uint16_t port) [constructor]
    cls.add_constructor([param('char const *', 'ipv6'), param('uint16_t', 'port')])
    ## inet6-socket-address.h (module 'network'): ns3::Inet6SocketAddress::Inet6SocketAddress(char const * ipv6) [constructor]
    cls.add_constructor([param('char const *', 'ipv6')])
    ## inet6-socket-address.h (module 'network'): static ns3::Inet6SocketAddress ns3::Inet6SocketAddress::ConvertFrom(ns3::Address const & addr) [member function]
    cls.add_method('ConvertFrom', 
                   'ns3::Inet6SocketAddress', 
                   [param('ns3::Address const &', 'addr')], 
                   is_static=True)
    ## inet6-socket-address.h (module 'network'): ns3::Ipv6Address ns3::Inet6SocketAddress::GetIpv6() const [member function]
    cls.add_method('GetIpv6', 
                   'ns3::Ipv6Address', 
                   [], 
                   is_const=True)
    ## inet6-socket-address.h (module 'network'): uint16_t ns3::Inet6SocketAddress::GetPort() const [member function]
    cls.add_method('GetPort', 
                   'uint16_t', 
                   [], 
                   is_const=True)
    ## inet6-socket-address.h (module 'network'): static bool ns3::Inet6SocketAddress::IsMatchingType(ns3::Address const & addr) [member function]
    cls.add_method('IsMatchingType', 
                   'bool', 
                   [param('ns3::Address const &', 'addr')], 
                   is_static=True)
    ## inet6-socket-address.h (module 'network'): void ns3::Inet6SocketAddress::SetIpv6(ns3::Ipv6Address ipv6) [member function]
    cls.add_method('SetIpv6', 
                   'void', 
                   [param('ns3::Ipv6Address', 'ipv6')])
    ## inet6-socket-address.h (module 'network'): void ns3::Inet6SocketAddress::SetPort(uint16_t port) [member function]
    cls.add_method('SetPort', 
                   'void', 
                   [param('uint16_t', 'port')])
    return

def register_Ns3InetSocketAddress_methods(root_module, cls):
    ## inet-socket-address.h (module 'network'): ns3::InetSocketAddress::InetSocketAddress(ns3::InetSocketAddress const & arg0) [constructor]
    cls.add_constructor([param('ns3::InetSocketAddress const &', 'arg0')])
    ## inet-socket-address.h (module 'network'): ns3::InetSocketAddress::InetSocketAddress(ns3::Ipv4Address ipv4, uint16_t port) [constructor]
    cls.add_constructor([param('ns3::Ipv4Address', 'ipv4'), param('uint16_t', 'port')])
    ## inet-socket-address.h (module 'network'): ns3::InetSocketAddress::InetSocketAddress(ns3::Ipv4Address ipv4) [constructor]
    cls.add_constructor([param('ns3::Ipv4Address', 'ipv4')])
    ## inet-socket-address.h (module 'network'): ns3::InetSocketAddress::InetSocketAddress(uint16_t port) [constructor]
    cls.add_constructor([param('uint16_t', 'port')])
    ## inet-socket-address.h (module 'network'): ns3::InetSocketAddress::InetSocketAddress(char const * ipv4, uint16_t port) [constructor]
    cls.add_constructor([param('char const *', 'ipv4'), param('uint16_t', 'port')])
    ## inet-socket-address.h (module 'network'): ns3::InetSocketAddress::InetSocketAddress(char const * ipv4) [constructor]
    cls.add_constructor([param('char const *', 'ipv4')])
    ## inet-socket-address.h (module 'network'): static ns3::InetSocketAddress ns3::InetSocketAddress::ConvertFrom(ns3::Address const & address) [member function]
    cls.add_method('ConvertFrom', 
                   'ns3::InetSocketAddress', 
                   [param('ns3::Address const &', 'address')], 
                   is_static=True)
    ## inet-socket-address.h (module 'network'): ns3::Ipv4Address ns3::InetSocketAddress::GetIpv4() const [member function]
    cls.add_method('GetIpv4', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## inet-socket-address.h (module 'network'): uint16_t ns3::InetSocketAddress::GetPort() const [member function]
    cls.add_method('GetPort', 
                   'uint16_t', 
                   [], 
                   is_const=True)
    ## inet-socket-address.h (module 'network'): uint8_t ns3::InetSocketAddress::GetTos() const [member function]
    cls.add_method('GetTos', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## inet-socket-address.h (module 'network'): static bool ns3::InetSocketAddress::IsMatchingType(ns3::Address const & address) [member function]
    cls.add_method('IsMatchingType', 
                   'bool', 
                   [param('ns3::Address const &', 'address')], 
                   is_static=True)
    ## inet-socket-address.h (module 'network'): void ns3::InetSocketAddress::SetIpv4(ns3::Ipv4Address address) [member function]
    cls.add_method('SetIpv4', 
                   'void', 
                   [param('ns3::Ipv4Address', 'address')])
    ## inet-socket-address.h (module 'network'): void ns3::InetSocketAddress::SetPort(uint16_t port) [member function]
    cls.add_method('SetPort', 
                   'void', 
                   [param('uint16_t', 'port')])
    ## inet-socket-address.h (module 'network'): void ns3::InetSocketAddress::SetTos(uint8_t tos) [member function]
    cls.add_method('SetTos', 
                   'void', 
                   [param('uint8_t', 'tos')])
    return

def register_Ns3IntToType__0_methods(root_module, cls):
    ## int-to-type.h (module 'core'): ns3::IntToType<0>::IntToType() [constructor]
    cls.add_constructor([])
    ## int-to-type.h (module 'core'): ns3::IntToType<0>::IntToType(ns3::IntToType<0> const & arg0) [constructor]
    cls.add_constructor([param('ns3::IntToType< 0 > const &', 'arg0')])
    return

def register_Ns3IntToType__1_methods(root_module, cls):
    ## int-to-type.h (module 'core'): ns3::IntToType<1>::IntToType() [constructor]
    cls.add_constructor([])
    ## int-to-type.h (module 'core'): ns3::IntToType<1>::IntToType(ns3::IntToType<1> const & arg0) [constructor]
    cls.add_constructor([param('ns3::IntToType< 1 > const &', 'arg0')])
    return

def register_Ns3IntToType__2_methods(root_module, cls):
    ## int-to-type.h (module 'core'): ns3::IntToType<2>::IntToType() [constructor]
    cls.add_constructor([])
    ## int-to-type.h (module 'core'): ns3::IntToType<2>::IntToType(ns3::IntToType<2> const & arg0) [constructor]
    cls.add_constructor([param('ns3::IntToType< 2 > const &', 'arg0')])
    return

def register_Ns3IntToType__3_methods(root_module, cls):
    ## int-to-type.h (module 'core'): ns3::IntToType<3>::IntToType() [constructor]
    cls.add_constructor([])
    ## int-to-type.h (module 'core'): ns3::IntToType<3>::IntToType(ns3::IntToType<3> const & arg0) [constructor]
    cls.add_constructor([param('ns3::IntToType< 3 > const &', 'arg0')])
    return

def register_Ns3IntToType__4_methods(root_module, cls):
    ## int-to-type.h (module 'core'): ns3::IntToType<4>::IntToType() [constructor]
    cls.add_constructor([])
    ## int-to-type.h (module 'core'): ns3::IntToType<4>::IntToType(ns3::IntToType<4> const & arg0) [constructor]
    cls.add_constructor([param('ns3::IntToType< 4 > const &', 'arg0')])
    return

def register_Ns3IntToType__5_methods(root_module, cls):
    ## int-to-type.h (module 'core'): ns3::IntToType<5>::IntToType() [constructor]
    cls.add_constructor([])
    ## int-to-type.h (module 'core'): ns3::IntToType<5>::IntToType(ns3::IntToType<5> const & arg0) [constructor]
    cls.add_constructor([param('ns3::IntToType< 5 > const &', 'arg0')])
    return

def register_Ns3IntToType__6_methods(root_module, cls):
    ## int-to-type.h (module 'core'): ns3::IntToType<6>::IntToType() [constructor]
    cls.add_constructor([])
    ## int-to-type.h (module 'core'): ns3::IntToType<6>::IntToType(ns3::IntToType<6> const & arg0) [constructor]
    cls.add_constructor([param('ns3::IntToType< 6 > const &', 'arg0')])
    return

def register_Ns3Ipv4Address_methods(root_module, cls):
    cls.add_output_stream_operator()
    cls.add_binary_comparison_operator('==')
    cls.add_binary_comparison_operator('!=')
    cls.add_binary_comparison_operator('<')
    ## ipv4-address.h (module 'network'): ns3::Ipv4Address::Ipv4Address(ns3::Ipv4Address const & arg0) [constructor]
    cls.add_constructor([param('ns3::Ipv4Address const &', 'arg0')])
    ## ipv4-address.h (module 'network'): ns3::Ipv4Address::Ipv4Address() [constructor]
    cls.add_constructor([])
    ## ipv4-address.h (module 'network'): ns3::Ipv4Address::Ipv4Address(uint32_t address) [constructor]
    cls.add_constructor([param('uint32_t', 'address')])
    ## ipv4-address.h (module 'network'): ns3::Ipv4Address::Ipv4Address(char const * address) [constructor]
    cls.add_constructor([param('char const *', 'address')])
    ## ipv4-address.h (module 'network'): ns3::Ipv4Address ns3::Ipv4Address::CombineMask(ns3::Ipv4Mask const & mask) const [member function]
    cls.add_method('CombineMask', 
                   'ns3::Ipv4Address', 
                   [param('ns3::Ipv4Mask const &', 'mask')], 
                   is_const=True)
    ## ipv4-address.h (module 'network'): static ns3::Ipv4Address ns3::Ipv4Address::ConvertFrom(ns3::Address const & address) [member function]
    cls.add_method('ConvertFrom', 
                   'ns3::Ipv4Address', 
                   [param('ns3::Address const &', 'address')], 
                   is_static=True)
    ## ipv4-address.h (module 'network'): static ns3::Ipv4Address ns3::Ipv4Address::Deserialize(uint8_t const * buf) [member function]
    cls.add_method('Deserialize', 
                   'ns3::Ipv4Address', 
                   [param('uint8_t const *', 'buf')], 
                   is_static=True)
    ## ipv4-address.h (module 'network'): uint32_t ns3::Ipv4Address::Get() const [member function]
    cls.add_method('Get', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## ipv4-address.h (module 'network'): static ns3::Ipv4Address ns3::Ipv4Address::GetAny() [member function]
    cls.add_method('GetAny', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_static=True)
    ## ipv4-address.h (module 'network'): static ns3::Ipv4Address ns3::Ipv4Address::GetBroadcast() [member function]
    cls.add_method('GetBroadcast', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_static=True)
    ## ipv4-address.h (module 'network'): static ns3::Ipv4Address ns3::Ipv4Address::GetLoopback() [member function]
    cls.add_method('GetLoopback', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_static=True)
    ## ipv4-address.h (module 'network'): ns3::Ipv4Address ns3::Ipv4Address::GetSubnetDirectedBroadcast(ns3::Ipv4Mask const & mask) const [member function]
    cls.add_method('GetSubnetDirectedBroadcast', 
                   'ns3::Ipv4Address', 
                   [param('ns3::Ipv4Mask const &', 'mask')], 
                   is_const=True)
    ## ipv4-address.h (module 'network'): static ns3::Ipv4Address ns3::Ipv4Address::GetZero() [member function]
    cls.add_method('GetZero', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_static=True)
    ## ipv4-address.h (module 'network'): bool ns3::Ipv4Address::IsAny() const [member function]
    cls.add_method('IsAny', 
                   'bool', 
                   [], 
                   is_const=True)
    ## ipv4-address.h (module 'network'): bool ns3::Ipv4Address::IsBroadcast() const [member function]
    cls.add_method('IsBroadcast', 
                   'bool', 
                   [], 
                   is_const=True)
    ## ipv4-address.h (module 'network'): bool ns3::Ipv4Address::IsEqual(ns3::Ipv4Address const & other) const [member function]
    cls.add_method('IsEqual', 
                   'bool', 
                   [param('ns3::Ipv4Address const &', 'other')], 
                   is_const=True)
    ## ipv4-address.h (module 'network'): bool ns3::Ipv4Address::IsLocalMulticast() const [member function]
    cls.add_method('IsLocalMulticast', 
                   'bool', 
                   [], 
                   is_const=True)
    ## ipv4-address.h (module 'network'): bool ns3::Ipv4Address::IsLocalhost() const [member function]
    cls.add_method('IsLocalhost', 
                   'bool', 
                   [], 
                   is_const=True)
    ## ipv4-address.h (module 'network'): static bool ns3::Ipv4Address::IsMatchingType(ns3::Address const & address) [member function]
    cls.add_method('IsMatchingType', 
                   'bool', 
                   [param('ns3::Address const &', 'address')], 
                   is_static=True)
    ## ipv4-address.h (module 'network'): bool ns3::Ipv4Address::IsMulticast() const [member function]
    cls.add_method('IsMulticast', 
                   'bool', 
                   [], 
                   is_const=True)
    ## ipv4-address.h (module 'network'): bool ns3::Ipv4Address::IsSubnetDirectedBroadcast(ns3::Ipv4Mask const & mask) const [member function]
    cls.add_method('IsSubnetDirectedBroadcast', 
                   'bool', 
                   [param('ns3::Ipv4Mask const &', 'mask')], 
                   is_const=True)
    ## ipv4-address.h (module 'network'): void ns3::Ipv4Address::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True)
    ## ipv4-address.h (module 'network'): void ns3::Ipv4Address::Serialize(uint8_t * buf) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('uint8_t *', 'buf')], 
                   is_const=True)
    ## ipv4-address.h (module 'network'): void ns3::Ipv4Address::Set(uint32_t address) [member function]
    cls.add_method('Set', 
                   'void', 
                   [param('uint32_t', 'address')])
    ## ipv4-address.h (module 'network'): void ns3::Ipv4Address::Set(char const * address) [member function]
    cls.add_method('Set', 
                   'void', 
                   [param('char const *', 'address')])
    return

def register_Ns3Ipv4InterfaceAddress_methods(root_module, cls):
    cls.add_output_stream_operator()
    cls.add_binary_comparison_operator('==')
    cls.add_binary_comparison_operator('!=')
    ## ipv4-interface-address.h (module 'internet'): ns3::Ipv4InterfaceAddress::Ipv4InterfaceAddress() [constructor]
    cls.add_constructor([])
    ## ipv4-interface-address.h (module 'internet'): ns3::Ipv4InterfaceAddress::Ipv4InterfaceAddress(ns3::Ipv4Address local, ns3::Ipv4Mask mask) [constructor]
    cls.add_constructor([param('ns3::Ipv4Address', 'local'), param('ns3::Ipv4Mask', 'mask')])
    ## ipv4-interface-address.h (module 'internet'): ns3::Ipv4InterfaceAddress::Ipv4InterfaceAddress(ns3::Ipv4InterfaceAddress const & o) [constructor]
    cls.add_constructor([param('ns3::Ipv4InterfaceAddress const &', 'o')])
    ## ipv4-interface-address.h (module 'internet'): ns3::Ipv4Address ns3::Ipv4InterfaceAddress::GetBroadcast() const [member function]
    cls.add_method('GetBroadcast', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## ipv4-interface-address.h (module 'internet'): ns3::Ipv4Address ns3::Ipv4InterfaceAddress::GetLocal() const [member function]
    cls.add_method('GetLocal', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## ipv4-interface-address.h (module 'internet'): ns3::Ipv4Mask ns3::Ipv4InterfaceAddress::GetMask() const [member function]
    cls.add_method('GetMask', 
                   'ns3::Ipv4Mask', 
                   [], 
                   is_const=True)
    ## ipv4-interface-address.h (module 'internet'): ns3::Ipv4InterfaceAddress::InterfaceAddressScope_e ns3::Ipv4InterfaceAddress::GetScope() const [member function]
    cls.add_method('GetScope', 
                   'ns3::Ipv4InterfaceAddress::InterfaceAddressScope_e', 
                   [], 
                   is_const=True)
    ## ipv4-interface-address.h (module 'internet'): bool ns3::Ipv4InterfaceAddress::IsSecondary() const [member function]
    cls.add_method('IsSecondary', 
                   'bool', 
                   [], 
                   is_const=True)
    ## ipv4-interface-address.h (module 'internet'): void ns3::Ipv4InterfaceAddress::SetBroadcast(ns3::Ipv4Address broadcast) [member function]
    cls.add_method('SetBroadcast', 
                   'void', 
                   [param('ns3::Ipv4Address', 'broadcast')])
    ## ipv4-interface-address.h (module 'internet'): void ns3::Ipv4InterfaceAddress::SetLocal(ns3::Ipv4Address local) [member function]
    cls.add_method('SetLocal', 
                   'void', 
                   [param('ns3::Ipv4Address', 'local')])
    ## ipv4-interface-address.h (module 'internet'): void ns3::Ipv4InterfaceAddress::SetMask(ns3::Ipv4Mask mask) [member function]
    cls.add_method('SetMask', 
                   'void', 
                   [param('ns3::Ipv4Mask', 'mask')])
    ## ipv4-interface-address.h (module 'internet'): void ns3::Ipv4InterfaceAddress::SetPrimary() [member function]
    cls.add_method('SetPrimary', 
                   'void', 
                   [])
    ## ipv4-interface-address.h (module 'internet'): void ns3::Ipv4InterfaceAddress::SetScope(ns3::Ipv4InterfaceAddress::InterfaceAddressScope_e scope) [member function]
    cls.add_method('SetScope', 
                   'void', 
                   [param('ns3::Ipv4InterfaceAddress::InterfaceAddressScope_e', 'scope')])
    ## ipv4-interface-address.h (module 'internet'): void ns3::Ipv4InterfaceAddress::SetSecondary() [member function]
    cls.add_method('SetSecondary', 
                   'void', 
                   [])
    return

def register_Ns3Ipv4Mask_methods(root_module, cls):
    cls.add_output_stream_operator()
    cls.add_binary_comparison_operator('==')
    cls.add_binary_comparison_operator('!=')
    ## ipv4-address.h (module 'network'): ns3::Ipv4Mask::Ipv4Mask(ns3::Ipv4Mask const & arg0) [constructor]
    cls.add_constructor([param('ns3::Ipv4Mask const &', 'arg0')])
    ## ipv4-address.h (module 'network'): ns3::Ipv4Mask::Ipv4Mask() [constructor]
    cls.add_constructor([])
    ## ipv4-address.h (module 'network'): ns3::Ipv4Mask::Ipv4Mask(uint32_t mask) [constructor]
    cls.add_constructor([param('uint32_t', 'mask')])
    ## ipv4-address.h (module 'network'): ns3::Ipv4Mask::Ipv4Mask(char const * mask) [constructor]
    cls.add_constructor([param('char const *', 'mask')])
    ## ipv4-address.h (module 'network'): uint32_t ns3::Ipv4Mask::Get() const [member function]
    cls.add_method('Get', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## ipv4-address.h (module 'network'): uint32_t ns3::Ipv4Mask::GetInverse() const [member function]
    cls.add_method('GetInverse', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## ipv4-address.h (module 'network'): static ns3::Ipv4Mask ns3::Ipv4Mask::GetLoopback() [member function]
    cls.add_method('GetLoopback', 
                   'ns3::Ipv4Mask', 
                   [], 
                   is_static=True)
    ## ipv4-address.h (module 'network'): static ns3::Ipv4Mask ns3::Ipv4Mask::GetOnes() [member function]
    cls.add_method('GetOnes', 
                   'ns3::Ipv4Mask', 
                   [], 
                   is_static=True)
    ## ipv4-address.h (module 'network'): uint16_t ns3::Ipv4Mask::GetPrefixLength() const [member function]
    cls.add_method('GetPrefixLength', 
                   'uint16_t', 
                   [], 
                   is_const=True)
    ## ipv4-address.h (module 'network'): static ns3::Ipv4Mask ns3::Ipv4Mask::GetZero() [member function]
    cls.add_method('GetZero', 
                   'ns3::Ipv4Mask', 
                   [], 
                   is_static=True)
    ## ipv4-address.h (module 'network'): bool ns3::Ipv4Mask::IsEqual(ns3::Ipv4Mask other) const [member function]
    cls.add_method('IsEqual', 
                   'bool', 
                   [param('ns3::Ipv4Mask', 'other')], 
                   is_const=True)
    ## ipv4-address.h (module 'network'): bool ns3::Ipv4Mask::IsMatch(ns3::Ipv4Address a, ns3::Ipv4Address b) const [member function]
    cls.add_method('IsMatch', 
                   'bool', 
                   [param('ns3::Ipv4Address', 'a'), param('ns3::Ipv4Address', 'b')], 
                   is_const=True)
    ## ipv4-address.h (module 'network'): void ns3::Ipv4Mask::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True)
    ## ipv4-address.h (module 'network'): void ns3::Ipv4Mask::Set(uint32_t mask) [member function]
    cls.add_method('Set', 
                   'void', 
                   [param('uint32_t', 'mask')])
    return

def register_Ns3Ipv6Address_methods(root_module, cls):
    cls.add_output_stream_operator()
    cls.add_binary_comparison_operator('==')
    cls.add_binary_comparison_operator('!=')
    cls.add_binary_comparison_operator('<')
    ## ipv6-address.h (module 'network'): ns3::Ipv6Address::Ipv6Address() [constructor]
    cls.add_constructor([])
    ## ipv6-address.h (module 'network'): ns3::Ipv6Address::Ipv6Address(char const * address) [constructor]
    cls.add_constructor([param('char const *', 'address')])
    ## ipv6-address.h (module 'network'): ns3::Ipv6Address::Ipv6Address(uint8_t * address) [constructor]
    cls.add_constructor([param('uint8_t *', 'address')])
    ## ipv6-address.h (module 'network'): ns3::Ipv6Address::Ipv6Address(ns3::Ipv6Address const & addr) [constructor]
    cls.add_constructor([param('ns3::Ipv6Address const &', 'addr')])
    ## ipv6-address.h (module 'network'): ns3::Ipv6Address::Ipv6Address(ns3::Ipv6Address const * addr) [constructor]
    cls.add_constructor([param('ns3::Ipv6Address const *', 'addr')])
    ## ipv6-address.h (module 'network'): ns3::Ipv6Address ns3::Ipv6Address::CombinePrefix(ns3::Ipv6Prefix const & prefix) [member function]
    cls.add_method('CombinePrefix', 
                   'ns3::Ipv6Address', 
                   [param('ns3::Ipv6Prefix const &', 'prefix')])
    ## ipv6-address.h (module 'network'): static ns3::Ipv6Address ns3::Ipv6Address::ConvertFrom(ns3::Address const & address) [member function]
    cls.add_method('ConvertFrom', 
                   'ns3::Ipv6Address', 
                   [param('ns3::Address const &', 'address')], 
                   is_static=True)
    ## ipv6-address.h (module 'network'): static ns3::Ipv6Address ns3::Ipv6Address::Deserialize(uint8_t const * buf) [member function]
    cls.add_method('Deserialize', 
                   'ns3::Ipv6Address', 
                   [param('uint8_t const *', 'buf')], 
                   is_static=True)
    ## ipv6-address.h (module 'network'): static ns3::Ipv6Address ns3::Ipv6Address::GetAllHostsMulticast() [member function]
    cls.add_method('GetAllHostsMulticast', 
                   'ns3::Ipv6Address', 
                   [], 
                   is_static=True)
    ## ipv6-address.h (module 'network'): static ns3::Ipv6Address ns3::Ipv6Address::GetAllNodesMulticast() [member function]
    cls.add_method('GetAllNodesMulticast', 
                   'ns3::Ipv6Address', 
                   [], 
                   is_static=True)
    ## ipv6-address.h (module 'network'): static ns3::Ipv6Address ns3::Ipv6Address::GetAllRoutersMulticast() [member function]
    cls.add_method('GetAllRoutersMulticast', 
                   'ns3::Ipv6Address', 
                   [], 
                   is_static=True)
    ## ipv6-address.h (module 'network'): static ns3::Ipv6Address ns3::Ipv6Address::GetAny() [member function]
    cls.add_method('GetAny', 
                   'ns3::Ipv6Address', 
                   [], 
                   is_static=True)
    ## ipv6-address.h (module 'network'): void ns3::Ipv6Address::GetBytes(uint8_t * buf) const [member function]
    cls.add_method('GetBytes', 
                   'void', 
                   [param('uint8_t *', 'buf')], 
                   is_const=True)
    ## ipv6-address.h (module 'network'): ns3::Ipv4Address ns3::Ipv6Address::GetIpv4MappedAddress() const [member function]
    cls.add_method('GetIpv4MappedAddress', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## ipv6-address.h (module 'network'): static ns3::Ipv6Address ns3::Ipv6Address::GetLoopback() [member function]
    cls.add_method('GetLoopback', 
                   'ns3::Ipv6Address', 
                   [], 
                   is_static=True)
    ## ipv6-address.h (module 'network'): static ns3::Ipv6Address ns3::Ipv6Address::GetOnes() [member function]
    cls.add_method('GetOnes', 
                   'ns3::Ipv6Address', 
                   [], 
                   is_static=True)
    ## ipv6-address.h (module 'network'): static ns3::Ipv6Address ns3::Ipv6Address::GetZero() [member function]
    cls.add_method('GetZero', 
                   'ns3::Ipv6Address', 
                   [], 
                   is_static=True)
    ## ipv6-address.h (module 'network'): bool ns3::Ipv6Address::IsAllHostsMulticast() const [member function]
    cls.add_method('IsAllHostsMulticast', 
                   'bool', 
                   [], 
                   deprecated=True, is_const=True)
    ## ipv6-address.h (module 'network'): bool ns3::Ipv6Address::IsAllNodesMulticast() const [member function]
    cls.add_method('IsAllNodesMulticast', 
                   'bool', 
                   [], 
                   is_const=True)
    ## ipv6-address.h (module 'network'): bool ns3::Ipv6Address::IsAllRoutersMulticast() const [member function]
    cls.add_method('IsAllRoutersMulticast', 
                   'bool', 
                   [], 
                   is_const=True)
    ## ipv6-address.h (module 'network'): bool ns3::Ipv6Address::IsAny() const [member function]
    cls.add_method('IsAny', 
                   'bool', 
                   [], 
                   is_const=True)
    ## ipv6-address.h (module 'network'): bool ns3::Ipv6Address::IsDocumentation() const [member function]
    cls.add_method('IsDocumentation', 
                   'bool', 
                   [], 
                   is_const=True)
    ## ipv6-address.h (module 'network'): bool ns3::Ipv6Address::IsEqual(ns3::Ipv6Address const & other) const [member function]
    cls.add_method('IsEqual', 
                   'bool', 
                   [param('ns3::Ipv6Address const &', 'other')], 
                   is_const=True)
    ## ipv6-address.h (module 'network'): bool ns3::Ipv6Address::IsIpv4MappedAddress() const [member function]
    cls.add_method('IsIpv4MappedAddress', 
                   'bool', 
                   [], 
                   is_const=True)
    ## ipv6-address.h (module 'network'): bool ns3::Ipv6Address::IsLinkLocal() const [member function]
    cls.add_method('IsLinkLocal', 
                   'bool', 
                   [], 
                   is_const=True)
    ## ipv6-address.h (module 'network'): bool ns3::Ipv6Address::IsLinkLocalMulticast() const [member function]
    cls.add_method('IsLinkLocalMulticast', 
                   'bool', 
                   [], 
                   is_const=True)
    ## ipv6-address.h (module 'network'): bool ns3::Ipv6Address::IsLocalhost() const [member function]
    cls.add_method('IsLocalhost', 
                   'bool', 
                   [], 
                   is_const=True)
    ## ipv6-address.h (module 'network'): static bool ns3::Ipv6Address::IsMatchingType(ns3::Address const & address) [member function]
    cls.add_method('IsMatchingType', 
                   'bool', 
                   [param('ns3::Address const &', 'address')], 
                   is_static=True)
    ## ipv6-address.h (module 'network'): bool ns3::Ipv6Address::IsMulticast() const [member function]
    cls.add_method('IsMulticast', 
                   'bool', 
                   [], 
                   is_const=True)
    ## ipv6-address.h (module 'network'): bool ns3::Ipv6Address::IsSolicitedMulticast() const [member function]
    cls.add_method('IsSolicitedMulticast', 
                   'bool', 
                   [], 
                   is_const=True)
    ## ipv6-address.h (module 'network'): static ns3::Ipv6Address ns3::Ipv6Address::MakeAutoconfiguredAddress(ns3::Mac16Address addr, ns3::Ipv6Address prefix) [member function]
    cls.add_method('MakeAutoconfiguredAddress', 
                   'ns3::Ipv6Address', 
                   [param('ns3::Mac16Address', 'addr'), param('ns3::Ipv6Address', 'prefix')], 
                   is_static=True)
    ## ipv6-address.h (module 'network'): static ns3::Ipv6Address ns3::Ipv6Address::MakeAutoconfiguredAddress(ns3::Mac48Address addr, ns3::Ipv6Address prefix) [member function]
    cls.add_method('MakeAutoconfiguredAddress', 
                   'ns3::Ipv6Address', 
                   [param('ns3::Mac48Address', 'addr'), param('ns3::Ipv6Address', 'prefix')], 
                   is_static=True)
    ## ipv6-address.h (module 'network'): static ns3::Ipv6Address ns3::Ipv6Address::MakeAutoconfiguredAddress(ns3::Mac64Address addr, ns3::Ipv6Address prefix) [member function]
    cls.add_method('MakeAutoconfiguredAddress', 
                   'ns3::Ipv6Address', 
                   [param('ns3::Mac64Address', 'addr'), param('ns3::Ipv6Address', 'prefix')], 
                   is_static=True)
    ## ipv6-address.h (module 'network'): static ns3::Ipv6Address ns3::Ipv6Address::MakeAutoconfiguredAddress(ns3::Mac8Address addr, ns3::Ipv6Address prefix) [member function]
    cls.add_method('MakeAutoconfiguredAddress', 
                   'ns3::Ipv6Address', 
                   [param('ns3::Mac8Address', 'addr'), param('ns3::Ipv6Address', 'prefix')], 
                   is_static=True)
    ## ipv6-address.h (module 'network'): static ns3::Ipv6Address ns3::Ipv6Address::MakeAutoconfiguredLinkLocalAddress(ns3::Mac16Address mac) [member function]
    cls.add_method('MakeAutoconfiguredLinkLocalAddress', 
                   'ns3::Ipv6Address', 
                   [param('ns3::Mac16Address', 'mac')], 
                   is_static=True)
    ## ipv6-address.h (module 'network'): static ns3::Ipv6Address ns3::Ipv6Address::MakeAutoconfiguredLinkLocalAddress(ns3::Mac48Address mac) [member function]
    cls.add_method('MakeAutoconfiguredLinkLocalAddress', 
                   'ns3::Ipv6Address', 
                   [param('ns3::Mac48Address', 'mac')], 
                   is_static=True)
    ## ipv6-address.h (module 'network'): static ns3::Ipv6Address ns3::Ipv6Address::MakeAutoconfiguredLinkLocalAddress(ns3::Mac64Address mac) [member function]
    cls.add_method('MakeAutoconfiguredLinkLocalAddress', 
                   'ns3::Ipv6Address', 
                   [param('ns3::Mac64Address', 'mac')], 
                   is_static=True)
    ## ipv6-address.h (module 'network'): static ns3::Ipv6Address ns3::Ipv6Address::MakeAutoconfiguredLinkLocalAddress(ns3::Mac8Address mac) [member function]
    cls.add_method('MakeAutoconfiguredLinkLocalAddress', 
                   'ns3::Ipv6Address', 
                   [param('ns3::Mac8Address', 'mac')], 
                   is_static=True)
    ## ipv6-address.h (module 'network'): static ns3::Ipv6Address ns3::Ipv6Address::MakeIpv4MappedAddress(ns3::Ipv4Address addr) [member function]
    cls.add_method('MakeIpv4MappedAddress', 
                   'ns3::Ipv6Address', 
                   [param('ns3::Ipv4Address', 'addr')], 
                   is_static=True)
    ## ipv6-address.h (module 'network'): static ns3::Ipv6Address ns3::Ipv6Address::MakeSolicitedAddress(ns3::Ipv6Address addr) [member function]
    cls.add_method('MakeSolicitedAddress', 
                   'ns3::Ipv6Address', 
                   [param('ns3::Ipv6Address', 'addr')], 
                   is_static=True)
    ## ipv6-address.h (module 'network'): void ns3::Ipv6Address::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True)
    ## ipv6-address.h (module 'network'): void ns3::Ipv6Address::Serialize(uint8_t * buf) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('uint8_t *', 'buf')], 
                   is_const=True)
    ## ipv6-address.h (module 'network'): void ns3::Ipv6Address::Set(char const * address) [member function]
    cls.add_method('Set', 
                   'void', 
                   [param('char const *', 'address')])
    ## ipv6-address.h (module 'network'): void ns3::Ipv6Address::Set(uint8_t * address) [member function]
    cls.add_method('Set', 
                   'void', 
                   [param('uint8_t *', 'address')])
    return

def register_Ns3Ipv6Prefix_methods(root_module, cls):
    cls.add_output_stream_operator()
    cls.add_binary_comparison_operator('==')
    cls.add_binary_comparison_operator('!=')
    ## ipv6-address.h (module 'network'): ns3::Ipv6Prefix::Ipv6Prefix() [constructor]
    cls.add_constructor([])
    ## ipv6-address.h (module 'network'): ns3::Ipv6Prefix::Ipv6Prefix(uint8_t * prefix) [constructor]
    cls.add_constructor([param('uint8_t *', 'prefix')])
    ## ipv6-address.h (module 'network'): ns3::Ipv6Prefix::Ipv6Prefix(char const * prefix) [constructor]
    cls.add_constructor([param('char const *', 'prefix')])
    ## ipv6-address.h (module 'network'): ns3::Ipv6Prefix::Ipv6Prefix(uint8_t prefix) [constructor]
    cls.add_constructor([param('uint8_t', 'prefix')])
    ## ipv6-address.h (module 'network'): ns3::Ipv6Prefix::Ipv6Prefix(ns3::Ipv6Prefix const & prefix) [constructor]
    cls.add_constructor([param('ns3::Ipv6Prefix const &', 'prefix')])
    ## ipv6-address.h (module 'network'): ns3::Ipv6Prefix::Ipv6Prefix(ns3::Ipv6Prefix const * prefix) [constructor]
    cls.add_constructor([param('ns3::Ipv6Prefix const *', 'prefix')])
    ## ipv6-address.h (module 'network'): void ns3::Ipv6Prefix::GetBytes(uint8_t * buf) const [member function]
    cls.add_method('GetBytes', 
                   'void', 
                   [param('uint8_t *', 'buf')], 
                   is_const=True)
    ## ipv6-address.h (module 'network'): static ns3::Ipv6Prefix ns3::Ipv6Prefix::GetLoopback() [member function]
    cls.add_method('GetLoopback', 
                   'ns3::Ipv6Prefix', 
                   [], 
                   is_static=True)
    ## ipv6-address.h (module 'network'): static ns3::Ipv6Prefix ns3::Ipv6Prefix::GetOnes() [member function]
    cls.add_method('GetOnes', 
                   'ns3::Ipv6Prefix', 
                   [], 
                   is_static=True)
    ## ipv6-address.h (module 'network'): uint8_t ns3::Ipv6Prefix::GetPrefixLength() const [member function]
    cls.add_method('GetPrefixLength', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## ipv6-address.h (module 'network'): static ns3::Ipv6Prefix ns3::Ipv6Prefix::GetZero() [member function]
    cls.add_method('GetZero', 
                   'ns3::Ipv6Prefix', 
                   [], 
                   is_static=True)
    ## ipv6-address.h (module 'network'): bool ns3::Ipv6Prefix::IsEqual(ns3::Ipv6Prefix const & other) const [member function]
    cls.add_method('IsEqual', 
                   'bool', 
                   [param('ns3::Ipv6Prefix const &', 'other')], 
                   is_const=True)
    ## ipv6-address.h (module 'network'): bool ns3::Ipv6Prefix::IsMatch(ns3::Ipv6Address a, ns3::Ipv6Address b) const [member function]
    cls.add_method('IsMatch', 
                   'bool', 
                   [param('ns3::Ipv6Address', 'a'), param('ns3::Ipv6Address', 'b')], 
                   is_const=True)
    ## ipv6-address.h (module 'network'): void ns3::Ipv6Prefix::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True)
    return

def register_Ns3Mac48Address_methods(root_module, cls):
    cls.add_binary_comparison_operator('==')
    cls.add_binary_comparison_operator('!=')
    cls.add_binary_comparison_operator('<')
    cls.add_output_stream_operator()
    ## mac48-address.h (module 'network'): ns3::Mac48Address::Mac48Address(ns3::Mac48Address const & arg0) [constructor]
    cls.add_constructor([param('ns3::Mac48Address const &', 'arg0')])
    ## mac48-address.h (module 'network'): ns3::Mac48Address::Mac48Address() [constructor]
    cls.add_constructor([])
    ## mac48-address.h (module 'network'): ns3::Mac48Address::Mac48Address(char const * str) [constructor]
    cls.add_constructor([param('char const *', 'str')])
    ## mac48-address.h (module 'network'): static ns3::Mac48Address ns3::Mac48Address::Allocate() [member function]
    cls.add_method('Allocate', 
                   'ns3::Mac48Address', 
                   [], 
                   is_static=True)
    ## mac48-address.h (module 'network'): static ns3::Mac48Address ns3::Mac48Address::ConvertFrom(ns3::Address const & address) [member function]
    cls.add_method('ConvertFrom', 
                   'ns3::Mac48Address', 
                   [param('ns3::Address const &', 'address')], 
                   is_static=True)
    ## mac48-address.h (module 'network'): void ns3::Mac48Address::CopyFrom(uint8_t const * buffer) [member function]
    cls.add_method('CopyFrom', 
                   'void', 
                   [param('uint8_t const *', 'buffer')])
    ## mac48-address.h (module 'network'): void ns3::Mac48Address::CopyTo(uint8_t * buffer) const [member function]
    cls.add_method('CopyTo', 
                   'void', 
                   [param('uint8_t *', 'buffer')], 
                   is_const=True)
    ## mac48-address.h (module 'network'): static ns3::Mac48Address ns3::Mac48Address::GetBroadcast() [member function]
    cls.add_method('GetBroadcast', 
                   'ns3::Mac48Address', 
                   [], 
                   is_static=True)
    ## mac48-address.h (module 'network'): static ns3::Mac48Address ns3::Mac48Address::GetMulticast(ns3::Ipv4Address address) [member function]
    cls.add_method('GetMulticast', 
                   'ns3::Mac48Address', 
                   [param('ns3::Ipv4Address', 'address')], 
                   is_static=True)
    ## mac48-address.h (module 'network'): static ns3::Mac48Address ns3::Mac48Address::GetMulticast(ns3::Ipv6Address address) [member function]
    cls.add_method('GetMulticast', 
                   'ns3::Mac48Address', 
                   [param('ns3::Ipv6Address', 'address')], 
                   is_static=True)
    ## mac48-address.h (module 'network'): static ns3::Mac48Address ns3::Mac48Address::GetMulticast6Prefix() [member function]
    cls.add_method('GetMulticast6Prefix', 
                   'ns3::Mac48Address', 
                   [], 
                   is_static=True)
    ## mac48-address.h (module 'network'): static ns3::Mac48Address ns3::Mac48Address::GetMulticastPrefix() [member function]
    cls.add_method('GetMulticastPrefix', 
                   'ns3::Mac48Address', 
                   [], 
                   is_static=True)
    ## mac48-address.h (module 'network'): bool ns3::Mac48Address::IsBroadcast() const [member function]
    cls.add_method('IsBroadcast', 
                   'bool', 
                   [], 
                   is_const=True)
    ## mac48-address.h (module 'network'): bool ns3::Mac48Address::IsGroup() const [member function]
    cls.add_method('IsGroup', 
                   'bool', 
                   [], 
                   is_const=True)
    ## mac48-address.h (module 'network'): static bool ns3::Mac48Address::IsMatchingType(ns3::Address const & address) [member function]
    cls.add_method('IsMatchingType', 
                   'bool', 
                   [param('ns3::Address const &', 'address')], 
                   is_static=True)
    return

def register_Ns3Mac8Address_methods(root_module, cls):
    cls.add_binary_comparison_operator('<')
    cls.add_binary_comparison_operator('==')
    cls.add_binary_comparison_operator('!=')
    cls.add_output_stream_operator()
    ## mac8-address.h (module 'network'): ns3::Mac8Address::Mac8Address(ns3::Mac8Address const & arg0) [constructor]
    cls.add_constructor([param('ns3::Mac8Address const &', 'arg0')])
    ## mac8-address.h (module 'network'): ns3::Mac8Address::Mac8Address() [constructor]
    cls.add_constructor([])
    ## mac8-address.h (module 'network'): ns3::Mac8Address::Mac8Address(uint8_t addr) [constructor]
    cls.add_constructor([param('uint8_t', 'addr')])
    ## mac8-address.h (module 'network'): static ns3::Mac8Address ns3::Mac8Address::Allocate() [member function]
    cls.add_method('Allocate', 
                   'ns3::Mac8Address', 
                   [], 
                   is_static=True)
    ## mac8-address.h (module 'network'): static ns3::Mac8Address ns3::Mac8Address::ConvertFrom(ns3::Address const & address) [member function]
    cls.add_method('ConvertFrom', 
                   'ns3::Mac8Address', 
                   [param('ns3::Address const &', 'address')], 
                   is_static=True)
    ## mac8-address.h (module 'network'): void ns3::Mac8Address::CopyFrom(uint8_t const * pBuffer) [member function]
    cls.add_method('CopyFrom', 
                   'void', 
                   [param('uint8_t const *', 'pBuffer')])
    ## mac8-address.h (module 'network'): void ns3::Mac8Address::CopyTo(uint8_t * pBuffer) const [member function]
    cls.add_method('CopyTo', 
                   'void', 
                   [param('uint8_t *', 'pBuffer')], 
                   is_const=True)
    ## mac8-address.h (module 'network'): static ns3::Mac8Address ns3::Mac8Address::GetBroadcast() [member function]
    cls.add_method('GetBroadcast', 
                   'ns3::Mac8Address', 
                   [], 
                   is_static=True)
    ## mac8-address.h (module 'network'): static bool ns3::Mac8Address::IsMatchingType(ns3::Address const & address) [member function]
    cls.add_method('IsMatchingType', 
                   'bool', 
                   [param('ns3::Address const &', 'address')], 
                   is_static=True)
    return

def register_Ns3NodeContainer_methods(root_module, cls):
    ## node-container.h (module 'network'): ns3::NodeContainer::NodeContainer(ns3::NodeContainer const & arg0) [constructor]
    cls.add_constructor([param('ns3::NodeContainer const &', 'arg0')])
    ## node-container.h (module 'network'): ns3::NodeContainer::NodeContainer() [constructor]
    cls.add_constructor([])
    ## node-container.h (module 'network'): ns3::NodeContainer::NodeContainer(ns3::Ptr<ns3::Node> node) [constructor]
    cls.add_constructor([param('ns3::Ptr< ns3::Node >', 'node')])
    ## node-container.h (module 'network'): ns3::NodeContainer::NodeContainer(std::string nodeName) [constructor]
    cls.add_constructor([param('std::string', 'nodeName')])
    ## node-container.h (module 'network'): ns3::NodeContainer::NodeContainer(ns3::NodeContainer const & a, ns3::NodeContainer const & b) [constructor]
    cls.add_constructor([param('ns3::NodeContainer const &', 'a'), param('ns3::NodeContainer const &', 'b')])
    ## node-container.h (module 'network'): ns3::NodeContainer::NodeContainer(ns3::NodeContainer const & a, ns3::NodeContainer const & b, ns3::NodeContainer const & c) [constructor]
    cls.add_constructor([param('ns3::NodeContainer const &', 'a'), param('ns3::NodeContainer const &', 'b'), param('ns3::NodeContainer const &', 'c')])
    ## node-container.h (module 'network'): ns3::NodeContainer::NodeContainer(ns3::NodeContainer const & a, ns3::NodeContainer const & b, ns3::NodeContainer const & c, ns3::NodeContainer const & d) [constructor]
    cls.add_constructor([param('ns3::NodeContainer const &', 'a'), param('ns3::NodeContainer const &', 'b'), param('ns3::NodeContainer const &', 'c'), param('ns3::NodeContainer const &', 'd')])
    ## node-container.h (module 'network'): ns3::NodeContainer::NodeContainer(ns3::NodeContainer const & a, ns3::NodeContainer const & b, ns3::NodeContainer const & c, ns3::NodeContainer const & d, ns3::NodeContainer const & e) [constructor]
    cls.add_constructor([param('ns3::NodeContainer const &', 'a'), param('ns3::NodeContainer const &', 'b'), param('ns3::NodeContainer const &', 'c'), param('ns3::NodeContainer const &', 'd'), param('ns3::NodeContainer const &', 'e')])
    ## node-container.h (module 'network'): void ns3::NodeContainer::Add(ns3::NodeContainer other) [member function]
    cls.add_method('Add', 
                   'void', 
                   [param('ns3::NodeContainer', 'other')])
    ## node-container.h (module 'network'): void ns3::NodeContainer::Add(ns3::Ptr<ns3::Node> node) [member function]
    cls.add_method('Add', 
                   'void', 
                   [param('ns3::Ptr< ns3::Node >', 'node')])
    ## node-container.h (module 'network'): void ns3::NodeContainer::Add(std::string nodeName) [member function]
    cls.add_method('Add', 
                   'void', 
                   [param('std::string', 'nodeName')])
    ## node-container.h (module 'network'): ns3::NodeContainer::Iterator ns3::NodeContainer::Begin() const [member function]
    cls.add_method('Begin', 
                   'ns3::NodeContainer::Iterator', 
                   [], 
                   is_const=True)
    ## node-container.h (module 'network'): bool ns3::NodeContainer::Contains(uint32_t id) const [member function]
    cls.add_method('Contains', 
                   'bool', 
                   [param('uint32_t', 'id')], 
                   is_const=True)
    ## node-container.h (module 'network'): void ns3::NodeContainer::Create(uint32_t n) [member function]
    cls.add_method('Create', 
                   'void', 
                   [param('uint32_t', 'n')])
    ## node-container.h (module 'network'): void ns3::NodeContainer::Create(uint32_t n, uint32_t systemId) [member function]
    cls.add_method('Create', 
                   'void', 
                   [param('uint32_t', 'n'), param('uint32_t', 'systemId')])
    ## node-container.h (module 'network'): ns3::NodeContainer::Iterator ns3::NodeContainer::End() const [member function]
    cls.add_method('End', 
                   'ns3::NodeContainer::Iterator', 
                   [], 
                   is_const=True)
    ## node-container.h (module 'network'): ns3::Ptr<ns3::Node> ns3::NodeContainer::Get(uint32_t i) const [member function]
    cls.add_method('Get', 
                   'ns3::Ptr< ns3::Node >', 
                   [param('uint32_t', 'i')], 
                   is_const=True)
    ## node-container.h (module 'network'): static ns3::NodeContainer ns3::NodeContainer::GetGlobal() [member function]
    cls.add_method('GetGlobal', 
                   'ns3::NodeContainer', 
                   [], 
                   is_static=True)
    ## node-container.h (module 'network'): uint32_t ns3::NodeContainer::GetN() const [member function]
    cls.add_method('GetN', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    return

def register_Ns3NonCopyable_methods(root_module, cls):
    ## non-copyable.h (module 'core'): ns3::NonCopyable::NonCopyable() [constructor]
    cls.add_constructor([], 
                        visibility='protected')
    return

def register_Ns3ObjectBase_methods(root_module, cls):
    ## object-base.h (module 'core'): ns3::ObjectBase::ObjectBase() [constructor]
    cls.add_constructor([])
    ## object-base.h (module 'core'): ns3::ObjectBase::ObjectBase(ns3::ObjectBase const & arg0) [constructor]
    cls.add_constructor([param('ns3::ObjectBase const &', 'arg0')])
    ## object-base.h (module 'core'): void ns3::ObjectBase::GetAttribute(std::string name, ns3::AttributeValue & value) const [member function]
    cls.add_method('GetAttribute', 
                   'void', 
                   [param('std::string', 'name'), param('ns3::AttributeValue &', 'value')], 
                   is_const=True)
    ## object-base.h (module 'core'): bool ns3::ObjectBase::GetAttributeFailSafe(std::string name, ns3::AttributeValue & value) const [member function]
    cls.add_method('GetAttributeFailSafe', 
                   'bool', 
                   [param('std::string', 'name'), param('ns3::AttributeValue &', 'value')], 
                   is_const=True)
    ## object-base.h (module 'core'): ns3::TypeId ns3::ObjectBase::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## object-base.h (module 'core'): static ns3::TypeId ns3::ObjectBase::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## object-base.h (module 'core'): void ns3::ObjectBase::SetAttribute(std::string name, ns3::AttributeValue const & value) [member function]
    cls.add_method('SetAttribute', 
                   'void', 
                   [param('std::string', 'name'), param('ns3::AttributeValue const &', 'value')])
    ## object-base.h (module 'core'): bool ns3::ObjectBase::SetAttributeFailSafe(std::string name, ns3::AttributeValue const & value) [member function]
    cls.add_method('SetAttributeFailSafe', 
                   'bool', 
                   [param('std::string', 'name'), param('ns3::AttributeValue const &', 'value')])
    ## object-base.h (module 'core'): bool ns3::ObjectBase::TraceConnect(std::string name, std::string context, ns3::CallbackBase const & cb) [member function]
    cls.add_method('TraceConnect', 
                   'bool', 
                   [param('std::string', 'name'), param('std::string', 'context'), param('ns3::CallbackBase const &', 'cb')])
    ## object-base.h (module 'core'): bool ns3::ObjectBase::TraceConnectWithoutContext(std::string name, ns3::CallbackBase const & cb) [member function]
    cls.add_method('TraceConnectWithoutContext', 
                   'bool', 
                   [param('std::string', 'name'), param('ns3::CallbackBase const &', 'cb')])
    ## object-base.h (module 'core'): bool ns3::ObjectBase::TraceDisconnect(std::string name, std::string context, ns3::CallbackBase const & cb) [member function]
    cls.add_method('TraceDisconnect', 
                   'bool', 
                   [param('std::string', 'name'), param('std::string', 'context'), param('ns3::CallbackBase const &', 'cb')])
    ## object-base.h (module 'core'): bool ns3::ObjectBase::TraceDisconnectWithoutContext(std::string name, ns3::CallbackBase const & cb) [member function]
    cls.add_method('TraceDisconnectWithoutContext', 
                   'bool', 
                   [param('std::string', 'name'), param('ns3::CallbackBase const &', 'cb')])
    ## object-base.h (module 'core'): void ns3::ObjectBase::ConstructSelf(ns3::AttributeConstructionList const & attributes) [member function]
    cls.add_method('ConstructSelf', 
                   'void', 
                   [param('ns3::AttributeConstructionList const &', 'attributes')], 
                   visibility='protected')
    ## object-base.h (module 'core'): void ns3::ObjectBase::NotifyConstructionCompleted() [member function]
    cls.add_method('NotifyConstructionCompleted', 
                   'void', 
                   [], 
                   visibility='protected', is_virtual=True)
    return

def register_Ns3ObjectDeleter_methods(root_module, cls):
    ## object.h (module 'core'): ns3::ObjectDeleter::ObjectDeleter() [constructor]
    cls.add_constructor([])
    ## object.h (module 'core'): ns3::ObjectDeleter::ObjectDeleter(ns3::ObjectDeleter const & arg0) [constructor]
    cls.add_constructor([param('ns3::ObjectDeleter const &', 'arg0')])
    ## object.h (module 'core'): static void ns3::ObjectDeleter::Delete(ns3::Object * object) [member function]
    cls.add_method('Delete', 
                   'void', 
                   [param('ns3::Object *', 'object')], 
                   is_static=True)
    return

def register_Ns3ObjectFactory_methods(root_module, cls):
    cls.add_output_stream_operator()
    ## object-factory.h (module 'core'): ns3::ObjectFactory::ObjectFactory(ns3::ObjectFactory const & arg0) [constructor]
    cls.add_constructor([param('ns3::ObjectFactory const &', 'arg0')])
    ## object-factory.h (module 'core'): ns3::ObjectFactory::ObjectFactory() [constructor]
    cls.add_constructor([])
    ## object-factory.h (module 'core'): ns3::ObjectFactory::ObjectFactory(std::string typeId) [constructor]
    cls.add_constructor([param('std::string', 'typeId')])
    ## object-factory.h (module 'core'): ns3::Ptr<ns3::Object> ns3::ObjectFactory::Create() const [member function]
    cls.add_method('Create', 
                   'ns3::Ptr< ns3::Object >', 
                   [], 
                   is_const=True)
    ## object-factory.h (module 'core'): ns3::TypeId ns3::ObjectFactory::GetTypeId() const [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True)
    ## object-factory.h (module 'core'): void ns3::ObjectFactory::Set(std::string name, ns3::AttributeValue const & value) [member function]
    cls.add_method('Set', 
                   'void', 
                   [param('std::string', 'name'), param('ns3::AttributeValue const &', 'value')])
    ## object-factory.h (module 'core'): void ns3::ObjectFactory::SetTypeId(ns3::TypeId tid) [member function]
    cls.add_method('SetTypeId', 
                   'void', 
                   [param('ns3::TypeId', 'tid')])
    ## object-factory.h (module 'core'): void ns3::ObjectFactory::SetTypeId(char const * tid) [member function]
    cls.add_method('SetTypeId', 
                   'void', 
                   [param('char const *', 'tid')])
    ## object-factory.h (module 'core'): void ns3::ObjectFactory::SetTypeId(std::string tid) [member function]
    cls.add_method('SetTypeId', 
                   'void', 
                   [param('std::string', 'tid')])
    return

def register_Ns3PacketMetadata_methods(root_module, cls):
    ## packet-metadata.h (module 'network'): ns3::PacketMetadata::PacketMetadata(uint64_t uid, uint32_t size) [constructor]
    cls.add_constructor([param('uint64_t', 'uid'), param('uint32_t', 'size')])
    ## packet-metadata.h (module 'network'): ns3::PacketMetadata::PacketMetadata(ns3::PacketMetadata const & o) [constructor]
    cls.add_constructor([param('ns3::PacketMetadata const &', 'o')])
    ## packet-metadata.h (module 'network'): void ns3::PacketMetadata::AddAtEnd(ns3::PacketMetadata const & o) [member function]
    cls.add_method('AddAtEnd', 
                   'void', 
                   [param('ns3::PacketMetadata const &', 'o')])
    ## packet-metadata.h (module 'network'): void ns3::PacketMetadata::AddHeader(ns3::Header const & header, uint32_t size) [member function]
    cls.add_method('AddHeader', 
                   'void', 
                   [param('ns3::Header const &', 'header'), param('uint32_t', 'size')])
    ## packet-metadata.h (module 'network'): void ns3::PacketMetadata::AddPaddingAtEnd(uint32_t end) [member function]
    cls.add_method('AddPaddingAtEnd', 
                   'void', 
                   [param('uint32_t', 'end')])
    ## packet-metadata.h (module 'network'): void ns3::PacketMetadata::AddTrailer(ns3::Trailer const & trailer, uint32_t size) [member function]
    cls.add_method('AddTrailer', 
                   'void', 
                   [param('ns3::Trailer const &', 'trailer'), param('uint32_t', 'size')])
    ## packet-metadata.h (module 'network'): ns3::PacketMetadata::ItemIterator ns3::PacketMetadata::BeginItem(ns3::Buffer buffer) const [member function]
    cls.add_method('BeginItem', 
                   'ns3::PacketMetadata::ItemIterator', 
                   [param('ns3::Buffer', 'buffer')], 
                   is_const=True)
    ## packet-metadata.h (module 'network'): ns3::PacketMetadata ns3::PacketMetadata::CreateFragment(uint32_t start, uint32_t end) const [member function]
    cls.add_method('CreateFragment', 
                   'ns3::PacketMetadata', 
                   [param('uint32_t', 'start'), param('uint32_t', 'end')], 
                   is_const=True)
    ## packet-metadata.h (module 'network'): uint32_t ns3::PacketMetadata::Deserialize(uint8_t const * buffer, uint32_t size) [member function]
    cls.add_method('Deserialize', 
                   'uint32_t', 
                   [param('uint8_t const *', 'buffer'), param('uint32_t', 'size')])
    ## packet-metadata.h (module 'network'): static void ns3::PacketMetadata::Enable() [member function]
    cls.add_method('Enable', 
                   'void', 
                   [], 
                   is_static=True)
    ## packet-metadata.h (module 'network'): static void ns3::PacketMetadata::EnableChecking() [member function]
    cls.add_method('EnableChecking', 
                   'void', 
                   [], 
                   is_static=True)
    ## packet-metadata.h (module 'network'): uint32_t ns3::PacketMetadata::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## packet-metadata.h (module 'network'): uint64_t ns3::PacketMetadata::GetUid() const [member function]
    cls.add_method('GetUid', 
                   'uint64_t', 
                   [], 
                   is_const=True)
    ## packet-metadata.h (module 'network'): void ns3::PacketMetadata::RemoveAtEnd(uint32_t end) [member function]
    cls.add_method('RemoveAtEnd', 
                   'void', 
                   [param('uint32_t', 'end')])
    ## packet-metadata.h (module 'network'): void ns3::PacketMetadata::RemoveAtStart(uint32_t start) [member function]
    cls.add_method('RemoveAtStart', 
                   'void', 
                   [param('uint32_t', 'start')])
    ## packet-metadata.h (module 'network'): void ns3::PacketMetadata::RemoveHeader(ns3::Header const & header, uint32_t size) [member function]
    cls.add_method('RemoveHeader', 
                   'void', 
                   [param('ns3::Header const &', 'header'), param('uint32_t', 'size')])
    ## packet-metadata.h (module 'network'): void ns3::PacketMetadata::RemoveTrailer(ns3::Trailer const & trailer, uint32_t size) [member function]
    cls.add_method('RemoveTrailer', 
                   'void', 
                   [param('ns3::Trailer const &', 'trailer'), param('uint32_t', 'size')])
    ## packet-metadata.h (module 'network'): uint32_t ns3::PacketMetadata::Serialize(uint8_t * buffer, uint32_t maxSize) const [member function]
    cls.add_method('Serialize', 
                   'uint32_t', 
                   [param('uint8_t *', 'buffer'), param('uint32_t', 'maxSize')], 
                   is_const=True)
    return

def register_Ns3PacketMetadataItem_methods(root_module, cls):
    ## packet-metadata.h (module 'network'): ns3::PacketMetadata::Item::Item() [constructor]
    cls.add_constructor([])
    ## packet-metadata.h (module 'network'): ns3::PacketMetadata::Item::Item(ns3::PacketMetadata::Item const & arg0) [constructor]
    cls.add_constructor([param('ns3::PacketMetadata::Item const &', 'arg0')])
    ## packet-metadata.h (module 'network'): ns3::PacketMetadata::Item::current [variable]
    cls.add_instance_attribute('current', 'ns3::Buffer::Iterator', is_const=False)
    ## packet-metadata.h (module 'network'): ns3::PacketMetadata::Item::currentSize [variable]
    cls.add_instance_attribute('currentSize', 'uint32_t', is_const=False)
    ## packet-metadata.h (module 'network'): ns3::PacketMetadata::Item::currentTrimedFromEnd [variable]
    cls.add_instance_attribute('currentTrimedFromEnd', 'uint32_t', is_const=False)
    ## packet-metadata.h (module 'network'): ns3::PacketMetadata::Item::currentTrimedFromStart [variable]
    cls.add_instance_attribute('currentTrimedFromStart', 'uint32_t', is_const=False)
    ## packet-metadata.h (module 'network'): ns3::PacketMetadata::Item::isFragment [variable]
    cls.add_instance_attribute('isFragment', 'bool', is_const=False)
    ## packet-metadata.h (module 'network'): ns3::PacketMetadata::Item::tid [variable]
    cls.add_instance_attribute('tid', 'ns3::TypeId', is_const=False)
    ## packet-metadata.h (module 'network'): ns3::PacketMetadata::Item::type [variable]
    cls.add_instance_attribute('type', 'ns3::PacketMetadata::Item::ItemType', is_const=False)
    return

def register_Ns3PacketMetadataItemIterator_methods(root_module, cls):
    ## packet-metadata.h (module 'network'): ns3::PacketMetadata::ItemIterator::ItemIterator(ns3::PacketMetadata::ItemIterator const & arg0) [constructor]
    cls.add_constructor([param('ns3::PacketMetadata::ItemIterator const &', 'arg0')])
    ## packet-metadata.h (module 'network'): ns3::PacketMetadata::ItemIterator::ItemIterator(ns3::PacketMetadata const * metadata, ns3::Buffer buffer) [constructor]
    cls.add_constructor([param('ns3::PacketMetadata const *', 'metadata'), param('ns3::Buffer', 'buffer')])
    ## packet-metadata.h (module 'network'): bool ns3::PacketMetadata::ItemIterator::HasNext() const [member function]
    cls.add_method('HasNext', 
                   'bool', 
                   [], 
                   is_const=True)
    ## packet-metadata.h (module 'network'): ns3::PacketMetadata::Item ns3::PacketMetadata::ItemIterator::Next() [member function]
    cls.add_method('Next', 
                   'ns3::PacketMetadata::Item', 
                   [])
    return

def register_Ns3PacketTagIterator_methods(root_module, cls):
    ## packet.h (module 'network'): ns3::PacketTagIterator::PacketTagIterator(ns3::PacketTagIterator const & arg0) [constructor]
    cls.add_constructor([param('ns3::PacketTagIterator const &', 'arg0')])
    ## packet.h (module 'network'): bool ns3::PacketTagIterator::HasNext() const [member function]
    cls.add_method('HasNext', 
                   'bool', 
                   [], 
                   is_const=True)
    ## packet.h (module 'network'): ns3::PacketTagIterator::Item ns3::PacketTagIterator::Next() [member function]
    cls.add_method('Next', 
                   'ns3::PacketTagIterator::Item', 
                   [])
    return

def register_Ns3PacketTagIteratorItem_methods(root_module, cls):
    ## packet.h (module 'network'): ns3::PacketTagIterator::Item::Item(ns3::PacketTagIterator::Item const & arg0) [constructor]
    cls.add_constructor([param('ns3::PacketTagIterator::Item const &', 'arg0')])
    ## packet.h (module 'network'): void ns3::PacketTagIterator::Item::GetTag(ns3::Tag & tag) const [member function]
    cls.add_method('GetTag', 
                   'void', 
                   [param('ns3::Tag &', 'tag')], 
                   is_const=True)
    ## packet.h (module 'network'): ns3::TypeId ns3::PacketTagIterator::Item::GetTypeId() const [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True)
    return

def register_Ns3PacketTagList_methods(root_module, cls):
    ## packet-tag-list.h (module 'network'): ns3::PacketTagList::PacketTagList() [constructor]
    cls.add_constructor([])
    ## packet-tag-list.h (module 'network'): ns3::PacketTagList::PacketTagList(ns3::PacketTagList const & o) [constructor]
    cls.add_constructor([param('ns3::PacketTagList const &', 'o')])
    ## packet-tag-list.h (module 'network'): void ns3::PacketTagList::Add(ns3::Tag const & tag) const [member function]
    cls.add_method('Add', 
                   'void', 
                   [param('ns3::Tag const &', 'tag')], 
                   is_const=True)
    ## packet-tag-list.h (module 'network'): ns3::PacketTagList::TagData const * ns3::PacketTagList::Head() const [member function]
    cls.add_method('Head', 
                   'ns3::PacketTagList::TagData const *', 
                   [], 
                   is_const=True)
    ## packet-tag-list.h (module 'network'): bool ns3::PacketTagList::Peek(ns3::Tag & tag) const [member function]
    cls.add_method('Peek', 
                   'bool', 
                   [param('ns3::Tag &', 'tag')], 
                   is_const=True)
    ## packet-tag-list.h (module 'network'): bool ns3::PacketTagList::Remove(ns3::Tag & tag) [member function]
    cls.add_method('Remove', 
                   'bool', 
                   [param('ns3::Tag &', 'tag')])
    ## packet-tag-list.h (module 'network'): void ns3::PacketTagList::RemoveAll() [member function]
    cls.add_method('RemoveAll', 
                   'void', 
                   [])
    ## packet-tag-list.h (module 'network'): bool ns3::PacketTagList::Replace(ns3::Tag & tag) [member function]
    cls.add_method('Replace', 
                   'bool', 
                   [param('ns3::Tag &', 'tag')])
    return

def register_Ns3PacketTagListTagData_methods(root_module, cls):
    ## packet-tag-list.h (module 'network'): ns3::PacketTagList::TagData::TagData() [constructor]
    cls.add_constructor([])
    ## packet-tag-list.h (module 'network'): ns3::PacketTagList::TagData::TagData(ns3::PacketTagList::TagData const & arg0) [constructor]
    cls.add_constructor([param('ns3::PacketTagList::TagData const &', 'arg0')])
    ## packet-tag-list.h (module 'network'): ns3::PacketTagList::TagData::count [variable]
    cls.add_instance_attribute('count', 'uint32_t', is_const=False)
    ## packet-tag-list.h (module 'network'): ns3::PacketTagList::TagData::data [variable]
    cls.add_instance_attribute('data', 'uint8_t [ 1 ]', is_const=False)
    ## packet-tag-list.h (module 'network'): ns3::PacketTagList::TagData::next [variable]
    cls.add_instance_attribute('next', 'ns3::PacketTagList::TagData *', is_const=False)
    ## packet-tag-list.h (module 'network'): ns3::PacketTagList::TagData::size [variable]
    cls.add_instance_attribute('size', 'uint32_t', is_const=False)
    ## packet-tag-list.h (module 'network'): ns3::PacketTagList::TagData::tid [variable]
    cls.add_instance_attribute('tid', 'ns3::TypeId', is_const=False)
    return

def register_Ns3SimpleRefCount__Ns3Object_Ns3ObjectBase_Ns3ObjectDeleter_methods(root_module, cls):
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::Object, ns3::ObjectBase, ns3::ObjectDeleter>::SimpleRefCount() [constructor]
    cls.add_constructor([])
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::Object, ns3::ObjectBase, ns3::ObjectDeleter>::SimpleRefCount(ns3::SimpleRefCount<ns3::Object, ns3::ObjectBase, ns3::ObjectDeleter> const & o) [constructor]
    cls.add_constructor([param('ns3::SimpleRefCount< ns3::Object, ns3::ObjectBase, ns3::ObjectDeleter > const &', 'o')])
    return

def register_Ns3Simulator_methods(root_module, cls):
    ## simulator.h (module 'core'): ns3::Simulator::Simulator(ns3::Simulator const & arg0) [constructor]
    cls.add_constructor([param('ns3::Simulator const &', 'arg0')])
    ## simulator.h (module 'core'): static void ns3::Simulator::Cancel(ns3::EventId const & id) [member function]
    cls.add_method('Cancel', 
                   'void', 
                   [param('ns3::EventId const &', 'id')], 
                   is_static=True)
    ## simulator.h (module 'core'): static void ns3::Simulator::Destroy() [member function]
    cls.add_method('Destroy', 
                   'void', 
                   [], 
                   is_static=True)
    ## simulator.h (module 'core'): static uint32_t ns3::Simulator::GetContext() [member function]
    cls.add_method('GetContext', 
                   'uint32_t', 
                   [], 
                   is_static=True)
    ## simulator.h (module 'core'): static ns3::Time ns3::Simulator::GetDelayLeft(ns3::EventId const & id) [member function]
    cls.add_method('GetDelayLeft', 
                   'ns3::Time', 
                   [param('ns3::EventId const &', 'id')], 
                   is_static=True)
    ## simulator.h (module 'core'): static ns3::Ptr<ns3::SimulatorImpl> ns3::Simulator::GetImplementation() [member function]
    cls.add_method('GetImplementation', 
                   'ns3::Ptr< ns3::SimulatorImpl >', 
                   [], 
                   is_static=True)
    ## simulator.h (module 'core'): static ns3::Time ns3::Simulator::GetMaximumSimulationTime() [member function]
    cls.add_method('GetMaximumSimulationTime', 
                   'ns3::Time', 
                   [], 
                   is_static=True)
    ## simulator.h (module 'core'): static uint32_t ns3::Simulator::GetSystemId() [member function]
    cls.add_method('GetSystemId', 
                   'uint32_t', 
                   [], 
                   is_static=True)
    ## simulator.h (module 'core'): static bool ns3::Simulator::IsExpired(ns3::EventId const & id) [member function]
    cls.add_method('IsExpired', 
                   'bool', 
                   [param('ns3::EventId const &', 'id')], 
                   is_static=True)
    ## simulator.h (module 'core'): static bool ns3::Simulator::IsFinished() [member function]
    cls.add_method('IsFinished', 
                   'bool', 
                   [], 
                   is_static=True)
    ## simulator.h (module 'core'): static ns3::Time ns3::Simulator::Now() [member function]
    cls.add_method('Now', 
                   'ns3::Time', 
                   [], 
                   is_static=True)
    ## simulator.h (module 'core'): static void ns3::Simulator::Remove(ns3::EventId const & id) [member function]
    cls.add_method('Remove', 
                   'void', 
                   [param('ns3::EventId const &', 'id')], 
                   is_static=True)
    ## simulator.h (module 'core'): static void ns3::Simulator::SetImplementation(ns3::Ptr<ns3::SimulatorImpl> impl) [member function]
    cls.add_method('SetImplementation', 
                   'void', 
                   [param('ns3::Ptr< ns3::SimulatorImpl >', 'impl')], 
                   is_static=True)
    ## simulator.h (module 'core'): static void ns3::Simulator::SetScheduler(ns3::ObjectFactory schedulerFactory) [member function]
    cls.add_method('SetScheduler', 
                   'void', 
                   [param('ns3::ObjectFactory', 'schedulerFactory')], 
                   is_static=True)
    ## simulator.h (module 'core'): static void ns3::Simulator::Stop() [member function]
    cls.add_method('Stop', 
                   'void', 
                   [], 
                   is_static=True)
    ## simulator.h (module 'core'): static void ns3::Simulator::Stop(ns3::Time const & delay) [member function]
    cls.add_method('Stop', 
                   'void', 
                   [param('ns3::Time const &', 'delay')], 
                   is_static=True)
    return

def register_Ns3SystemWallClockMs_methods(root_module, cls):
    ## system-wall-clock-ms.h (module 'core'): ns3::SystemWallClockMs::SystemWallClockMs(ns3::SystemWallClockMs const & arg0) [constructor]
    cls.add_constructor([param('ns3::SystemWallClockMs const &', 'arg0')])
    ## system-wall-clock-ms.h (module 'core'): ns3::SystemWallClockMs::SystemWallClockMs() [constructor]
    cls.add_constructor([])
    ## system-wall-clock-ms.h (module 'core'): int64_t ns3::SystemWallClockMs::End() [member function]
    cls.add_method('End', 
                   'int64_t', 
                   [])
    ## system-wall-clock-ms.h (module 'core'): int64_t ns3::SystemWallClockMs::GetElapsedReal() const [member function]
    cls.add_method('GetElapsedReal', 
                   'int64_t', 
                   [], 
                   is_const=True)
    ## system-wall-clock-ms.h (module 'core'): int64_t ns3::SystemWallClockMs::GetElapsedSystem() const [member function]
    cls.add_method('GetElapsedSystem', 
                   'int64_t', 
                   [], 
                   is_const=True)
    ## system-wall-clock-ms.h (module 'core'): int64_t ns3::SystemWallClockMs::GetElapsedUser() const [member function]
    cls.add_method('GetElapsedUser', 
                   'int64_t', 
                   [], 
                   is_const=True)
    ## system-wall-clock-ms.h (module 'core'): void ns3::SystemWallClockMs::Start() [member function]
    cls.add_method('Start', 
                   'void', 
                   [])
    return

def register_Ns3Tag_methods(root_module, cls):
    ## tag.h (module 'network'): ns3::Tag::Tag() [constructor]
    cls.add_constructor([])
    ## tag.h (module 'network'): ns3::Tag::Tag(ns3::Tag const & arg0) [constructor]
    cls.add_constructor([param('ns3::Tag const &', 'arg0')])
    ## tag.h (module 'network'): void ns3::Tag::Deserialize(ns3::TagBuffer i) [member function]
    cls.add_method('Deserialize', 
                   'void', 
                   [param('ns3::TagBuffer', 'i')], 
                   is_pure_virtual=True, is_virtual=True)
    ## tag.h (module 'network'): uint32_t ns3::Tag::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## tag.h (module 'network'): static ns3::TypeId ns3::Tag::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## tag.h (module 'network'): void ns3::Tag::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## tag.h (module 'network'): void ns3::Tag::Serialize(ns3::TagBuffer i) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::TagBuffer', 'i')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    return

def register_Ns3TagBuffer_methods(root_module, cls):
    ## tag-buffer.h (module 'network'): ns3::TagBuffer::TagBuffer(ns3::TagBuffer const & arg0) [constructor]
    cls.add_constructor([param('ns3::TagBuffer const &', 'arg0')])
    ## tag-buffer.h (module 'network'): ns3::TagBuffer::TagBuffer(uint8_t * start, uint8_t * end) [constructor]
    cls.add_constructor([param('uint8_t *', 'start'), param('uint8_t *', 'end')])
    ## tag-buffer.h (module 'network'): void ns3::TagBuffer::CopyFrom(ns3::TagBuffer o) [member function]
    cls.add_method('CopyFrom', 
                   'void', 
                   [param('ns3::TagBuffer', 'o')])
    ## tag-buffer.h (module 'network'): void ns3::TagBuffer::Read(uint8_t * buffer, uint32_t size) [member function]
    cls.add_method('Read', 
                   'void', 
                   [param('uint8_t *', 'buffer'), param('uint32_t', 'size')])
    ## tag-buffer.h (module 'network'): double ns3::TagBuffer::ReadDouble() [member function]
    cls.add_method('ReadDouble', 
                   'double', 
                   [])
    ## tag-buffer.h (module 'network'): uint16_t ns3::TagBuffer::ReadU16() [member function]
    cls.add_method('ReadU16', 
                   'uint16_t', 
                   [])
    ## tag-buffer.h (module 'network'): uint32_t ns3::TagBuffer::ReadU32() [member function]
    cls.add_method('ReadU32', 
                   'uint32_t', 
                   [])
    ## tag-buffer.h (module 'network'): uint64_t ns3::TagBuffer::ReadU64() [member function]
    cls.add_method('ReadU64', 
                   'uint64_t', 
                   [])
    ## tag-buffer.h (module 'network'): uint8_t ns3::TagBuffer::ReadU8() [member function]
    cls.add_method('ReadU8', 
                   'uint8_t', 
                   [])
    ## tag-buffer.h (module 'network'): void ns3::TagBuffer::TrimAtEnd(uint32_t trim) [member function]
    cls.add_method('TrimAtEnd', 
                   'void', 
                   [param('uint32_t', 'trim')])
    ## tag-buffer.h (module 'network'): void ns3::TagBuffer::Write(uint8_t const * buffer, uint32_t size) [member function]
    cls.add_method('Write', 
                   'void', 
                   [param('uint8_t const *', 'buffer'), param('uint32_t', 'size')])
    ## tag-buffer.h (module 'network'): void ns3::TagBuffer::WriteDouble(double v) [member function]
    cls.add_method('WriteDouble', 
                   'void', 
                   [param('double', 'v')])
    ## tag-buffer.h (module 'network'): void ns3::TagBuffer::WriteU16(uint16_t v) [member function]
    cls.add_method('WriteU16', 
                   'void', 
                   [param('uint16_t', 'v')])
    ## tag-buffer.h (module 'network'): void ns3::TagBuffer::WriteU32(uint32_t v) [member function]
    cls.add_method('WriteU32', 
                   'void', 
                   [param('uint32_t', 'v')])
    ## tag-buffer.h (module 'network'): void ns3::TagBuffer::WriteU64(uint64_t v) [member function]
    cls.add_method('WriteU64', 
                   'void', 
                   [param('uint64_t', 'v')])
    ## tag-buffer.h (module 'network'): void ns3::TagBuffer::WriteU8(uint8_t v) [member function]
    cls.add_method('WriteU8', 
                   'void', 
                   [param('uint8_t', 'v')])
    return

def register_Ns3TimeWithUnit_methods(root_module, cls):
    cls.add_output_stream_operator()
    ## nstime.h (module 'core'): ns3::TimeWithUnit::TimeWithUnit(ns3::TimeWithUnit const & arg0) [constructor]
    cls.add_constructor([param('ns3::TimeWithUnit const &', 'arg0')])
    ## nstime.h (module 'core'): ns3::TimeWithUnit::TimeWithUnit(ns3::Time const time, ns3::Time::Unit const unit) [constructor]
    cls.add_constructor([param('ns3::Time const', 'time'), param('ns3::Time::Unit const', 'unit')])
    return

def register_Ns3Timer_methods(root_module, cls):
    ## timer.h (module 'core'): ns3::Timer::Timer(ns3::Timer const & arg0) [constructor]
    cls.add_constructor([param('ns3::Timer const &', 'arg0')])
    ## timer.h (module 'core'): ns3::Timer::Timer() [constructor]
    cls.add_constructor([])
    ## timer.h (module 'core'): ns3::Timer::Timer(ns3::Timer::DestroyPolicy destroyPolicy) [constructor]
    cls.add_constructor([param('ns3::Timer::DestroyPolicy', 'destroyPolicy')])
    ## timer.h (module 'core'): void ns3::Timer::Cancel() [member function]
    cls.add_method('Cancel', 
                   'void', 
                   [])
    ## timer.h (module 'core'): ns3::Time ns3::Timer::GetDelay() const [member function]
    cls.add_method('GetDelay', 
                   'ns3::Time', 
                   [], 
                   is_const=True)
    ## timer.h (module 'core'): ns3::Time ns3::Timer::GetDelayLeft() const [member function]
    cls.add_method('GetDelayLeft', 
                   'ns3::Time', 
                   [], 
                   is_const=True)
    ## timer.h (module 'core'): ns3::Timer::State ns3::Timer::GetState() const [member function]
    cls.add_method('GetState', 
                   'ns3::Timer::State', 
                   [], 
                   is_const=True)
    ## timer.h (module 'core'): bool ns3::Timer::IsExpired() const [member function]
    cls.add_method('IsExpired', 
                   'bool', 
                   [], 
                   is_const=True)
    ## timer.h (module 'core'): bool ns3::Timer::IsRunning() const [member function]
    cls.add_method('IsRunning', 
                   'bool', 
                   [], 
                   is_const=True)
    ## timer.h (module 'core'): bool ns3::Timer::IsSuspended() const [member function]
    cls.add_method('IsSuspended', 
                   'bool', 
                   [], 
                   is_const=True)
    ## timer.h (module 'core'): void ns3::Timer::Remove() [member function]
    cls.add_method('Remove', 
                   'void', 
                   [])
    ## timer.h (module 'core'): void ns3::Timer::Resume() [member function]
    cls.add_method('Resume', 
                   'void', 
                   [])
    ## timer.h (module 'core'): void ns3::Timer::Schedule() [member function]
    cls.add_method('Schedule', 
                   'void', 
                   [])
    ## timer.h (module 'core'): void ns3::Timer::Schedule(ns3::Time delay) [member function]
    cls.add_method('Schedule', 
                   'void', 
                   [param('ns3::Time', 'delay')])
    ## timer.h (module 'core'): void ns3::Timer::SetDelay(ns3::Time const & delay) [member function]
    cls.add_method('SetDelay', 
                   'void', 
                   [param('ns3::Time const &', 'delay')])
    ## timer.h (module 'core'): void ns3::Timer::Suspend() [member function]
    cls.add_method('Suspend', 
                   'void', 
                   [])
    return

def register_Ns3TimerImpl_methods(root_module, cls):
    ## timer-impl.h (module 'core'): ns3::TimerImpl::TimerImpl() [constructor]
    cls.add_constructor([])
    ## timer-impl.h (module 'core'): ns3::TimerImpl::TimerImpl(ns3::TimerImpl const & arg0) [constructor]
    cls.add_constructor([param('ns3::TimerImpl const &', 'arg0')])
    ## timer-impl.h (module 'core'): void ns3::TimerImpl::Invoke() [member function]
    cls.add_method('Invoke', 
                   'void', 
                   [], 
                   is_pure_virtual=True, is_virtual=True)
    ## timer-impl.h (module 'core'): ns3::EventId ns3::TimerImpl::Schedule(ns3::Time const & delay) [member function]
    cls.add_method('Schedule', 
                   'ns3::EventId', 
                   [param('ns3::Time const &', 'delay')], 
                   is_pure_virtual=True, is_virtual=True)
    return

def register_Ns3TypeId_methods(root_module, cls):
    cls.add_binary_comparison_operator('==')
    cls.add_binary_comparison_operator('!=')
    cls.add_output_stream_operator()
    cls.add_binary_comparison_operator('<')
    ## type-id.h (module 'core'): ns3::TypeId::TypeId(char const * name) [constructor]
    cls.add_constructor([param('char const *', 'name')])
    ## type-id.h (module 'core'): ns3::TypeId::TypeId() [constructor]
    cls.add_constructor([])
    ## type-id.h (module 'core'): ns3::TypeId::TypeId(ns3::TypeId const & o) [constructor]
    cls.add_constructor([param('ns3::TypeId const &', 'o')])
    ## type-id.h (module 'core'): ns3::TypeId ns3::TypeId::AddAttribute(std::string name, std::string help, ns3::AttributeValue const & initialValue, ns3::Ptr<const ns3::AttributeAccessor> accessor, ns3::Ptr<const ns3::AttributeChecker> checker, ns3::TypeId::SupportLevel supportLevel=::ns3::TypeId::SupportLevel::SUPPORTED, std::string const & supportMsg="") [member function]
    cls.add_method('AddAttribute', 
                   'ns3::TypeId', 
                   [param('std::string', 'name'), param('std::string', 'help'), param('ns3::AttributeValue const &', 'initialValue'), param('ns3::Ptr< ns3::AttributeAccessor const >', 'accessor'), param('ns3::Ptr< ns3::AttributeChecker const >', 'checker'), param('ns3::TypeId::SupportLevel', 'supportLevel', default_value='::ns3::TypeId::SupportLevel::SUPPORTED'), param('std::string const &', 'supportMsg', default_value='""')])
    ## type-id.h (module 'core'): ns3::TypeId ns3::TypeId::AddAttribute(std::string name, std::string help, uint32_t flags, ns3::AttributeValue const & initialValue, ns3::Ptr<const ns3::AttributeAccessor> accessor, ns3::Ptr<const ns3::AttributeChecker> checker, ns3::TypeId::SupportLevel supportLevel=::ns3::TypeId::SupportLevel::SUPPORTED, std::string const & supportMsg="") [member function]
    cls.add_method('AddAttribute', 
                   'ns3::TypeId', 
                   [param('std::string', 'name'), param('std::string', 'help'), param('uint32_t', 'flags'), param('ns3::AttributeValue const &', 'initialValue'), param('ns3::Ptr< ns3::AttributeAccessor const >', 'accessor'), param('ns3::Ptr< ns3::AttributeChecker const >', 'checker'), param('ns3::TypeId::SupportLevel', 'supportLevel', default_value='::ns3::TypeId::SupportLevel::SUPPORTED'), param('std::string const &', 'supportMsg', default_value='""')])
    ## type-id.h (module 'core'): ns3::TypeId ns3::TypeId::AddTraceSource(std::string name, std::string help, ns3::Ptr<const ns3::TraceSourceAccessor> accessor) [member function]
    cls.add_method('AddTraceSource', 
                   'ns3::TypeId', 
                   [param('std::string', 'name'), param('std::string', 'help'), param('ns3::Ptr< ns3::TraceSourceAccessor const >', 'accessor')], 
                   deprecated=True)
    ## type-id.h (module 'core'): ns3::TypeId ns3::TypeId::AddTraceSource(std::string name, std::string help, ns3::Ptr<const ns3::TraceSourceAccessor> accessor, std::string callback, ns3::TypeId::SupportLevel supportLevel=::ns3::TypeId::SupportLevel::SUPPORTED, std::string const & supportMsg="") [member function]
    cls.add_method('AddTraceSource', 
                   'ns3::TypeId', 
                   [param('std::string', 'name'), param('std::string', 'help'), param('ns3::Ptr< ns3::TraceSourceAccessor const >', 'accessor'), param('std::string', 'callback'), param('ns3::TypeId::SupportLevel', 'supportLevel', default_value='::ns3::TypeId::SupportLevel::SUPPORTED'), param('std::string const &', 'supportMsg', default_value='""')])
    ## type-id.h (module 'core'): ns3::TypeId::AttributeInformation ns3::TypeId::GetAttribute(std::size_t i) const [member function]
    cls.add_method('GetAttribute', 
                   'ns3::TypeId::AttributeInformation', 
                   [param('std::size_t', 'i')], 
                   is_const=True)
    ## type-id.h (module 'core'): std::string ns3::TypeId::GetAttributeFullName(std::size_t i) const [member function]
    cls.add_method('GetAttributeFullName', 
                   'std::string', 
                   [param('std::size_t', 'i')], 
                   is_const=True)
    ## type-id.h (module 'core'): std::size_t ns3::TypeId::GetAttributeN() const [member function]
    cls.add_method('GetAttributeN', 
                   'std::size_t', 
                   [], 
                   is_const=True)
    ## type-id.h (module 'core'): ns3::Callback<ns3::ObjectBase *, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> ns3::TypeId::GetConstructor() const [member function]
    cls.add_method('GetConstructor', 
                   'ns3::Callback< ns3::ObjectBase *, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 
                   [], 
                   is_const=True)
    ## type-id.h (module 'core'): std::string ns3::TypeId::GetGroupName() const [member function]
    cls.add_method('GetGroupName', 
                   'std::string', 
                   [], 
                   is_const=True)
    ## type-id.h (module 'core'): ns3::TypeId::hash_t ns3::TypeId::GetHash() const [member function]
    cls.add_method('GetHash', 
                   'ns3::TypeId::hash_t', 
                   [], 
                   is_const=True)
    ## type-id.h (module 'core'): std::string ns3::TypeId::GetName() const [member function]
    cls.add_method('GetName', 
                   'std::string', 
                   [], 
                   is_const=True)
    ## type-id.h (module 'core'): ns3::TypeId ns3::TypeId::GetParent() const [member function]
    cls.add_method('GetParent', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True)
    ## type-id.h (module 'core'): static ns3::TypeId ns3::TypeId::GetRegistered(uint16_t i) [member function]
    cls.add_method('GetRegistered', 
                   'ns3::TypeId', 
                   [param('uint16_t', 'i')], 
                   is_static=True)
    ## type-id.h (module 'core'): static uint16_t ns3::TypeId::GetRegisteredN() [member function]
    cls.add_method('GetRegisteredN', 
                   'uint16_t', 
                   [], 
                   is_static=True)
    ## type-id.h (module 'core'): std::size_t ns3::TypeId::GetSize() const [member function]
    cls.add_method('GetSize', 
                   'std::size_t', 
                   [], 
                   is_const=True)
    ## type-id.h (module 'core'): ns3::TypeId::TraceSourceInformation ns3::TypeId::GetTraceSource(std::size_t i) const [member function]
    cls.add_method('GetTraceSource', 
                   'ns3::TypeId::TraceSourceInformation', 
                   [param('std::size_t', 'i')], 
                   is_const=True)
    ## type-id.h (module 'core'): std::size_t ns3::TypeId::GetTraceSourceN() const [member function]
    cls.add_method('GetTraceSourceN', 
                   'std::size_t', 
                   [], 
                   is_const=True)
    ## type-id.h (module 'core'): uint16_t ns3::TypeId::GetUid() const [member function]
    cls.add_method('GetUid', 
                   'uint16_t', 
                   [], 
                   is_const=True)
    ## type-id.h (module 'core'): bool ns3::TypeId::HasConstructor() const [member function]
    cls.add_method('HasConstructor', 
                   'bool', 
                   [], 
                   is_const=True)
    ## type-id.h (module 'core'): bool ns3::TypeId::HasParent() const [member function]
    cls.add_method('HasParent', 
                   'bool', 
                   [], 
                   is_const=True)
    ## type-id.h (module 'core'): ns3::TypeId ns3::TypeId::HideFromDocumentation() [member function]
    cls.add_method('HideFromDocumentation', 
                   'ns3::TypeId', 
                   [])
    ## type-id.h (module 'core'): bool ns3::TypeId::IsChildOf(ns3::TypeId other) const [member function]
    cls.add_method('IsChildOf', 
                   'bool', 
                   [param('ns3::TypeId', 'other')], 
                   is_const=True)
    ## type-id.h (module 'core'): bool ns3::TypeId::LookupAttributeByName(std::string name, ns3::TypeId::AttributeInformation * info) const [member function]
    cls.add_method('LookupAttributeByName', 
                   'bool', 
                   [param('std::string', 'name'), param('ns3::TypeId::AttributeInformation *', 'info', transfer_ownership=False)], 
                   is_const=True)
    ## type-id.h (module 'core'): static ns3::TypeId ns3::TypeId::LookupByHash(ns3::TypeId::hash_t hash) [member function]
    cls.add_method('LookupByHash', 
                   'ns3::TypeId', 
                   [param('uint32_t', 'hash')], 
                   is_static=True)
    ## type-id.h (module 'core'): static bool ns3::TypeId::LookupByHashFailSafe(ns3::TypeId::hash_t hash, ns3::TypeId * tid) [member function]
    cls.add_method('LookupByHashFailSafe', 
                   'bool', 
                   [param('uint32_t', 'hash'), param('ns3::TypeId *', 'tid')], 
                   is_static=True)
    ## type-id.h (module 'core'): static ns3::TypeId ns3::TypeId::LookupByName(std::string name) [member function]
    cls.add_method('LookupByName', 
                   'ns3::TypeId', 
                   [param('std::string', 'name')], 
                   is_static=True)
    ## type-id.h (module 'core'): ns3::Ptr<const ns3::TraceSourceAccessor> ns3::TypeId::LookupTraceSourceByName(std::string name) const [member function]
    cls.add_method('LookupTraceSourceByName', 
                   'ns3::Ptr< ns3::TraceSourceAccessor const >', 
                   [param('std::string', 'name')], 
                   is_const=True)
    ## type-id.h (module 'core'): ns3::Ptr<const ns3::TraceSourceAccessor> ns3::TypeId::LookupTraceSourceByName(std::string name, ns3::TypeId::TraceSourceInformation * info) const [member function]
    cls.add_method('LookupTraceSourceByName', 
                   'ns3::Ptr< ns3::TraceSourceAccessor const >', 
                   [param('std::string', 'name'), param('ns3::TypeId::TraceSourceInformation *', 'info')], 
                   is_const=True)
    ## type-id.h (module 'core'): bool ns3::TypeId::MustHideFromDocumentation() const [member function]
    cls.add_method('MustHideFromDocumentation', 
                   'bool', 
                   [], 
                   is_const=True)
    ## type-id.h (module 'core'): bool ns3::TypeId::SetAttributeInitialValue(std::size_t i, ns3::Ptr<const ns3::AttributeValue> initialValue) [member function]
    cls.add_method('SetAttributeInitialValue', 
                   'bool', 
                   [param('std::size_t', 'i'), param('ns3::Ptr< ns3::AttributeValue const >', 'initialValue')])
    ## type-id.h (module 'core'): ns3::TypeId ns3::TypeId::SetGroupName(std::string groupName) [member function]
    cls.add_method('SetGroupName', 
                   'ns3::TypeId', 
                   [param('std::string', 'groupName')])
    ## type-id.h (module 'core'): ns3::TypeId ns3::TypeId::SetParent(ns3::TypeId tid) [member function]
    cls.add_method('SetParent', 
                   'ns3::TypeId', 
                   [param('ns3::TypeId', 'tid')])
    ## type-id.h (module 'core'): ns3::TypeId ns3::TypeId::SetSize(std::size_t size) [member function]
    cls.add_method('SetSize', 
                   'ns3::TypeId', 
                   [param('std::size_t', 'size')])
    ## type-id.h (module 'core'): void ns3::TypeId::SetUid(uint16_t uid) [member function]
    cls.add_method('SetUid', 
                   'void', 
                   [param('uint16_t', 'uid')])
    return

def register_Ns3TypeIdAttributeInformation_methods(root_module, cls):
    ## type-id.h (module 'core'): ns3::TypeId::AttributeInformation::AttributeInformation() [constructor]
    cls.add_constructor([])
    ## type-id.h (module 'core'): ns3::TypeId::AttributeInformation::AttributeInformation(ns3::TypeId::AttributeInformation const & arg0) [constructor]
    cls.add_constructor([param('ns3::TypeId::AttributeInformation const &', 'arg0')])
    ## type-id.h (module 'core'): ns3::TypeId::AttributeInformation::accessor [variable]
    cls.add_instance_attribute('accessor', 'ns3::Ptr< ns3::AttributeAccessor const >', is_const=False)
    ## type-id.h (module 'core'): ns3::TypeId::AttributeInformation::checker [variable]
    cls.add_instance_attribute('checker', 'ns3::Ptr< ns3::AttributeChecker const >', is_const=False)
    cls.add_instance_attribute('flags', 'uint32_t', is_const=False)
    ## type-id.h (module 'core'): ns3::TypeId::AttributeInformation::help [variable]
    cls.add_instance_attribute('help', 'std::string', is_const=False)
    ## type-id.h (module 'core'): ns3::TypeId::AttributeInformation::initialValue [variable]
    cls.add_instance_attribute('initialValue', 'ns3::Ptr< ns3::AttributeValue const >', is_const=False)
    ## type-id.h (module 'core'): ns3::TypeId::AttributeInformation::name [variable]
    cls.add_instance_attribute('name', 'std::string', is_const=False)
    ## type-id.h (module 'core'): ns3::TypeId::AttributeInformation::originalInitialValue [variable]
    cls.add_instance_attribute('originalInitialValue', 'ns3::Ptr< ns3::AttributeValue const >', is_const=False)
    ## type-id.h (module 'core'): ns3::TypeId::AttributeInformation::supportLevel [variable]
    cls.add_instance_attribute('supportLevel', 'ns3::TypeId::SupportLevel', is_const=False)
    ## type-id.h (module 'core'): ns3::TypeId::AttributeInformation::supportMsg [variable]
    cls.add_instance_attribute('supportMsg', 'std::string', is_const=False)
    return

def register_Ns3TypeIdTraceSourceInformation_methods(root_module, cls):
    ## type-id.h (module 'core'): ns3::TypeId::TraceSourceInformation::TraceSourceInformation() [constructor]
    cls.add_constructor([])
    ## type-id.h (module 'core'): ns3::TypeId::TraceSourceInformation::TraceSourceInformation(ns3::TypeId::TraceSourceInformation const & arg0) [constructor]
    cls.add_constructor([param('ns3::TypeId::TraceSourceInformation const &', 'arg0')])
    ## type-id.h (module 'core'): ns3::TypeId::TraceSourceInformation::accessor [variable]
    cls.add_instance_attribute('accessor', 'ns3::Ptr< ns3::TraceSourceAccessor const >', is_const=False)
    ## type-id.h (module 'core'): ns3::TypeId::TraceSourceInformation::callback [variable]
    cls.add_instance_attribute('callback', 'std::string', is_const=False)
    ## type-id.h (module 'core'): ns3::TypeId::TraceSourceInformation::help [variable]
    cls.add_instance_attribute('help', 'std::string', is_const=False)
    ## type-id.h (module 'core'): ns3::TypeId::TraceSourceInformation::name [variable]
    cls.add_instance_attribute('name', 'std::string', is_const=False)
    ## type-id.h (module 'core'): ns3::TypeId::TraceSourceInformation::supportLevel [variable]
    cls.add_instance_attribute('supportLevel', 'ns3::TypeId::SupportLevel', is_const=False)
    ## type-id.h (module 'core'): ns3::TypeId::TraceSourceInformation::supportMsg [variable]
    cls.add_instance_attribute('supportMsg', 'std::string', is_const=False)
    return

def register_Ns3WifiMode_methods(root_module, cls):
    cls.add_binary_comparison_operator('==')
    cls.add_binary_comparison_operator('<')
    cls.add_output_stream_operator()
    ## wifi-mode.h (module 'wifi'): ns3::WifiMode::WifiMode(ns3::WifiMode const & arg0) [constructor]
    cls.add_constructor([param('ns3::WifiMode const &', 'arg0')])
    ## wifi-mode.h (module 'wifi'): ns3::WifiMode::WifiMode() [constructor]
    cls.add_constructor([])
    ## wifi-mode.h (module 'wifi'): ns3::WifiMode::WifiMode(std::string name) [constructor]
    cls.add_constructor([param('std::string', 'name')])
    ## wifi-mode.h (module 'wifi'): ns3::WifiCodeRate ns3::WifiMode::GetCodeRate() const [member function]
    cls.add_method('GetCodeRate', 
                   'ns3::WifiCodeRate', 
                   [], 
                   is_const=True)
    ## wifi-mode.h (module 'wifi'): uint16_t ns3::WifiMode::GetConstellationSize() const [member function]
    cls.add_method('GetConstellationSize', 
                   'uint16_t', 
                   [], 
                   is_const=True)
    ## wifi-mode.h (module 'wifi'): uint64_t ns3::WifiMode::GetDataRate(uint16_t channelWidth, uint16_t guardInterval, uint8_t nss) const [member function]
    cls.add_method('GetDataRate', 
                   'uint64_t', 
                   [param('uint16_t', 'channelWidth'), param('uint16_t', 'guardInterval'), param('uint8_t', 'nss')], 
                   is_const=True)
    ## wifi-mode.h (module 'wifi'): uint64_t ns3::WifiMode::GetDataRate(ns3::WifiTxVector txVector) const [member function]
    cls.add_method('GetDataRate', 
                   'uint64_t', 
                   [param('ns3::WifiTxVector', 'txVector')], 
                   is_const=True)
    ## wifi-mode.h (module 'wifi'): uint64_t ns3::WifiMode::GetDataRate(uint16_t channelWidth) const [member function]
    cls.add_method('GetDataRate', 
                   'uint64_t', 
                   [param('uint16_t', 'channelWidth')], 
                   is_const=True)
    ## wifi-mode.h (module 'wifi'): uint8_t ns3::WifiMode::GetMcsValue() const [member function]
    cls.add_method('GetMcsValue', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## wifi-mode.h (module 'wifi'): ns3::WifiModulationClass ns3::WifiMode::GetModulationClass() const [member function]
    cls.add_method('GetModulationClass', 
                   'ns3::WifiModulationClass', 
                   [], 
                   is_const=True)
    ## wifi-mode.h (module 'wifi'): uint64_t ns3::WifiMode::GetNonHtReferenceRate() const [member function]
    cls.add_method('GetNonHtReferenceRate', 
                   'uint64_t', 
                   [], 
                   is_const=True)
    ## wifi-mode.h (module 'wifi'): uint64_t ns3::WifiMode::GetPhyRate(uint16_t channelWidth, uint16_t guardInterval, uint8_t nss) const [member function]
    cls.add_method('GetPhyRate', 
                   'uint64_t', 
                   [param('uint16_t', 'channelWidth'), param('uint16_t', 'guardInterval'), param('uint8_t', 'nss')], 
                   is_const=True)
    ## wifi-mode.h (module 'wifi'): uint64_t ns3::WifiMode::GetPhyRate(ns3::WifiTxVector txVector) const [member function]
    cls.add_method('GetPhyRate', 
                   'uint64_t', 
                   [param('ns3::WifiTxVector', 'txVector')], 
                   is_const=True)
    ## wifi-mode.h (module 'wifi'): uint32_t ns3::WifiMode::GetUid() const [member function]
    cls.add_method('GetUid', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## wifi-mode.h (module 'wifi'): std::string ns3::WifiMode::GetUniqueName() const [member function]
    cls.add_method('GetUniqueName', 
                   'std::string', 
                   [], 
                   is_const=True)
    ## wifi-mode.h (module 'wifi'): bool ns3::WifiMode::IsAllowed(uint16_t channelWidth, uint8_t nss) const [member function]
    cls.add_method('IsAllowed', 
                   'bool', 
                   [param('uint16_t', 'channelWidth'), param('uint8_t', 'nss')], 
                   is_const=True)
    ## wifi-mode.h (module 'wifi'): bool ns3::WifiMode::IsHigherCodeRate(ns3::WifiMode mode) const [member function]
    cls.add_method('IsHigherCodeRate', 
                   'bool', 
                   [param('ns3::WifiMode', 'mode')], 
                   is_const=True)
    ## wifi-mode.h (module 'wifi'): bool ns3::WifiMode::IsHigherDataRate(ns3::WifiMode mode) const [member function]
    cls.add_method('IsHigherDataRate', 
                   'bool', 
                   [param('ns3::WifiMode', 'mode')], 
                   is_const=True)
    ## wifi-mode.h (module 'wifi'): bool ns3::WifiMode::IsMandatory() const [member function]
    cls.add_method('IsMandatory', 
                   'bool', 
                   [], 
                   is_const=True)
    return

def register_Ns3WifiModeFactory_methods(root_module, cls):
    ## wifi-mode.h (module 'wifi'): ns3::WifiModeFactory::WifiModeFactory(ns3::WifiModeFactory const & arg0) [constructor]
    cls.add_constructor([param('ns3::WifiModeFactory const &', 'arg0')])
    ## wifi-mode.h (module 'wifi'): static ns3::WifiMode ns3::WifiModeFactory::CreateWifiMcs(std::string uniqueName, uint8_t mcsValue, ns3::WifiModulationClass modClass) [member function]
    cls.add_method('CreateWifiMcs', 
                   'ns3::WifiMode', 
                   [param('std::string', 'uniqueName'), param('uint8_t', 'mcsValue'), param('ns3::WifiModulationClass', 'modClass')], 
                   is_static=True)
    ## wifi-mode.h (module 'wifi'): static ns3::WifiMode ns3::WifiModeFactory::CreateWifiMode(std::string uniqueName, ns3::WifiModulationClass modClass, bool isMandatory, ns3::WifiCodeRate codingRate, uint16_t constellationSize) [member function]
    cls.add_method('CreateWifiMode', 
                   'ns3::WifiMode', 
                   [param('std::string', 'uniqueName'), param('ns3::WifiModulationClass', 'modClass'), param('bool', 'isMandatory'), param('ns3::WifiCodeRate', 'codingRate'), param('uint16_t', 'constellationSize')], 
                   is_static=True)
    return

def register_Ns3WifiRemoteStation_methods(root_module, cls):
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStation::WifiRemoteStation() [constructor]
    cls.add_constructor([])
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStation::WifiRemoteStation(ns3::WifiRemoteStation const & arg0) [constructor]
    cls.add_constructor([param('ns3::WifiRemoteStation const &', 'arg0')])
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStation::m_slrc [variable]
    cls.add_instance_attribute('m_slrc', 'uint32_t', is_const=False)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStation::m_ssrc [variable]
    cls.add_instance_attribute('m_ssrc', 'uint32_t', is_const=False)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStation::m_state [variable]
    cls.add_instance_attribute('m_state', 'ns3::WifiRemoteStationState *', is_const=False)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStation::m_tid [variable]
    cls.add_instance_attribute('m_tid', 'uint8_t', is_const=False)
    return

def register_Ns3WifiRemoteStationInfo_methods(root_module, cls):
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationInfo::WifiRemoteStationInfo(ns3::WifiRemoteStationInfo const & arg0) [constructor]
    cls.add_constructor([param('ns3::WifiRemoteStationInfo const &', 'arg0')])
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationInfo::WifiRemoteStationInfo() [constructor]
    cls.add_constructor([])
    ## wifi-remote-station-manager.h (module 'wifi'): double ns3::WifiRemoteStationInfo::GetFrameErrorRate() const [member function]
    cls.add_method('GetFrameErrorRate', 
                   'double', 
                   [], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationInfo::NotifyTxFailed() [member function]
    cls.add_method('NotifyTxFailed', 
                   'void', 
                   [])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationInfo::NotifyTxSuccess(uint32_t retryCounter) [member function]
    cls.add_method('NotifyTxSuccess', 
                   'void', 
                   [param('uint32_t', 'retryCounter')])
    return

def register_Ns3WifiRemoteStationState_methods(root_module, cls):
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationState::WifiRemoteStationState() [constructor]
    cls.add_constructor([])
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationState::WifiRemoteStationState(ns3::WifiRemoteStationState const & arg0) [constructor]
    cls.add_constructor([param('ns3::WifiRemoteStationState const &', 'arg0')])
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationState::m_address [variable]
    cls.add_instance_attribute('m_address', 'ns3::Mac48Address', is_const=False)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationState::m_aggregation [variable]
    cls.add_instance_attribute('m_aggregation', 'bool', is_const=False)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationState::m_channelWidth [variable]
    cls.add_instance_attribute('m_channelWidth', 'uint16_t', is_const=False)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationState::m_greenfield [variable]
    cls.add_instance_attribute('m_greenfield', 'bool', is_const=False)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationState::m_guardInterval [variable]
    cls.add_instance_attribute('m_guardInterval', 'uint16_t', is_const=False)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationState::m_heSupported [variable]
    cls.add_instance_attribute('m_heSupported', 'bool', is_const=False)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationState::m_htSupported [variable]
    cls.add_instance_attribute('m_htSupported', 'bool', is_const=False)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationState::m_info [variable]
    cls.add_instance_attribute('m_info', 'ns3::WifiRemoteStationInfo', is_const=False)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationState::m_ldpc [variable]
    cls.add_instance_attribute('m_ldpc', 'bool', is_const=False)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationState::m_ness [variable]
    cls.add_instance_attribute('m_ness', 'uint8_t', is_const=False)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationState::m_operationalMcsSet [variable]
    cls.add_instance_attribute('m_operationalMcsSet', 'ns3::WifiModeList', is_const=False)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationState::m_operationalRateSet [variable]
    cls.add_instance_attribute('m_operationalRateSet', 'ns3::WifiModeList', is_const=False)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationState::m_qosSupported [variable]
    cls.add_instance_attribute('m_qosSupported', 'bool', is_const=False)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationState::m_shortGuardInterval [variable]
    cls.add_instance_attribute('m_shortGuardInterval', 'bool', is_const=False)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationState::m_shortPreamble [variable]
    cls.add_instance_attribute('m_shortPreamble', 'bool', is_const=False)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationState::m_shortSlotTime [variable]
    cls.add_instance_attribute('m_shortSlotTime', 'bool', is_const=False)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationState::m_stbc [variable]
    cls.add_instance_attribute('m_stbc', 'bool', is_const=False)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationState::m_streams [variable]
    cls.add_instance_attribute('m_streams', 'uint8_t', is_const=False)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationState::m_vhtSupported [variable]
    cls.add_instance_attribute('m_vhtSupported', 'bool', is_const=False)
    return

def register_Ns3Empty_methods(root_module, cls):
    ## empty.h (module 'core'): ns3::empty::empty() [constructor]
    cls.add_constructor([])
    ## empty.h (module 'core'): ns3::empty::empty(ns3::empty const & arg0) [constructor]
    cls.add_constructor([param('ns3::empty const &', 'arg0')])
    return

def register_Ns3Int64x64_t_methods(root_module, cls):
    cls.add_binary_numeric_operator('+', root_module['ns3::int64x64_t'], root_module['ns3::int64x64_t'], param('ns3::int64x64_t const &', u'right'))
    cls.add_binary_numeric_operator('-', root_module['ns3::int64x64_t'], root_module['ns3::int64x64_t'], param('ns3::int64x64_t const &', u'right'))
    cls.add_binary_numeric_operator('*', root_module['ns3::int64x64_t'], root_module['ns3::int64x64_t'], param('ns3::int64x64_t const &', u'right'))
    cls.add_binary_numeric_operator('/', root_module['ns3::int64x64_t'], root_module['ns3::int64x64_t'], param('ns3::int64x64_t const &', u'right'))
    cls.add_binary_comparison_operator('!=')
    cls.add_binary_comparison_operator('<=')
    cls.add_binary_comparison_operator('>=')
    cls.add_output_stream_operator()
    cls.add_binary_comparison_operator('==')
    cls.add_binary_comparison_operator('<')
    cls.add_binary_comparison_operator('>')
    cls.add_inplace_numeric_operator('+=', param('ns3::int64x64_t const &', u'right'))
    cls.add_inplace_numeric_operator('-=', param('ns3::int64x64_t const &', u'right'))
    cls.add_inplace_numeric_operator('*=', param('ns3::int64x64_t const &', u'right'))
    cls.add_inplace_numeric_operator('/=', param('ns3::int64x64_t const &', u'right'))
    cls.add_unary_numeric_operator('-')
    ## int64x64-128.h (module 'core'): ns3::int64x64_t::int64x64_t() [constructor]
    cls.add_constructor([])
    ## int64x64-128.h (module 'core'): ns3::int64x64_t::int64x64_t(double const value) [constructor]
    cls.add_constructor([param('double const', 'value')])
    ## int64x64-128.h (module 'core'): ns3::int64x64_t::int64x64_t(long double const value) [constructor]
    cls.add_constructor([param('long double const', 'value')])
    ## int64x64-128.h (module 'core'): ns3::int64x64_t::int64x64_t(int const v) [constructor]
    cls.add_constructor([param('int const', 'v')])
    ## int64x64-128.h (module 'core'): ns3::int64x64_t::int64x64_t(long int const v) [constructor]
    cls.add_constructor([param('long int const', 'v')])
    ## int64x64-128.h (module 'core'): ns3::int64x64_t::int64x64_t(long long int const v) [constructor]
    cls.add_constructor([param('long long int const', 'v')])
    ## int64x64-128.h (module 'core'): ns3::int64x64_t::int64x64_t(unsigned int const v) [constructor]
    cls.add_constructor([param('unsigned int const', 'v')])
    ## int64x64-128.h (module 'core'): ns3::int64x64_t::int64x64_t(long unsigned int const v) [constructor]
    cls.add_constructor([param('long unsigned int const', 'v')])
    ## int64x64-128.h (module 'core'): ns3::int64x64_t::int64x64_t(long long unsigned int const v) [constructor]
    cls.add_constructor([param('long long unsigned int const', 'v')])
    ## int64x64-128.h (module 'core'): ns3::int64x64_t::int64x64_t(int64_t const hi, uint64_t const lo) [constructor]
    cls.add_constructor([param('int64_t const', 'hi'), param('uint64_t const', 'lo')])
    ## int64x64-128.h (module 'core'): ns3::int64x64_t::int64x64_t(ns3::int64x64_t const & o) [constructor]
    cls.add_constructor([param('ns3::int64x64_t const &', 'o')])
    ## int64x64-128.h (module 'core'): double ns3::int64x64_t::GetDouble() const [member function]
    cls.add_method('GetDouble', 
                   'double', 
                   [], 
                   is_const=True)
    ## int64x64-128.h (module 'core'): int64_t ns3::int64x64_t::GetHigh() const [member function]
    cls.add_method('GetHigh', 
                   'int64_t', 
                   [], 
                   is_const=True)
    ## int64x64-128.h (module 'core'): uint64_t ns3::int64x64_t::GetLow() const [member function]
    cls.add_method('GetLow', 
                   'uint64_t', 
                   [], 
                   is_const=True)
    ## int64x64-128.h (module 'core'): static ns3::int64x64_t ns3::int64x64_t::Invert(uint64_t const v) [member function]
    cls.add_method('Invert', 
                   'ns3::int64x64_t', 
                   [param('uint64_t const', 'v')], 
                   is_static=True)
    ## int64x64-128.h (module 'core'): void ns3::int64x64_t::MulByInvert(ns3::int64x64_t const & o) [member function]
    cls.add_method('MulByInvert', 
                   'void', 
                   [param('ns3::int64x64_t const &', 'o')])
    ## int64x64-128.h (module 'core'): ns3::int64x64_t::implementation [variable]
    cls.add_static_attribute('implementation', 'ns3::int64x64_t::impl_type const', is_const=True)
    return

def register_Ns3Chunk_methods(root_module, cls):
    ## chunk.h (module 'network'): ns3::Chunk::Chunk() [constructor]
    cls.add_constructor([])
    ## chunk.h (module 'network'): ns3::Chunk::Chunk(ns3::Chunk const & arg0) [constructor]
    cls.add_constructor([param('ns3::Chunk const &', 'arg0')])
    ## chunk.h (module 'network'): uint32_t ns3::Chunk::Deserialize(ns3::Buffer::Iterator start) [member function]
    cls.add_method('Deserialize', 
                   'uint32_t', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_pure_virtual=True, is_virtual=True)
    ## chunk.h (module 'network'): uint32_t ns3::Chunk::Deserialize(ns3::Buffer::Iterator start, ns3::Buffer::Iterator end) [member function]
    cls.add_method('Deserialize', 
                   'uint32_t', 
                   [param('ns3::Buffer::Iterator', 'start'), param('ns3::Buffer::Iterator', 'end')], 
                   is_virtual=True)
    ## chunk.h (module 'network'): static ns3::TypeId ns3::Chunk::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## chunk.h (module 'network'): void ns3::Chunk::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    return

def register_Ns3Header_methods(root_module, cls):
    cls.add_output_stream_operator()
    ## header.h (module 'network'): ns3::Header::Header() [constructor]
    cls.add_constructor([])
    ## header.h (module 'network'): ns3::Header::Header(ns3::Header const & arg0) [constructor]
    cls.add_constructor([param('ns3::Header const &', 'arg0')])
    ## header.h (module 'network'): uint32_t ns3::Header::Deserialize(ns3::Buffer::Iterator start) [member function]
    cls.add_method('Deserialize', 
                   'uint32_t', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_pure_virtual=True, is_virtual=True)
    ## header.h (module 'network'): uint32_t ns3::Header::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## header.h (module 'network'): static ns3::TypeId ns3::Header::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## header.h (module 'network'): void ns3::Header::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## header.h (module 'network'): void ns3::Header::Serialize(ns3::Buffer::Iterator start) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    return

def register_Ns3Icmpv4DestinationUnreachable_methods(root_module, cls):
    ## icmpv4.h (module 'internet'): ns3::Icmpv4DestinationUnreachable::Icmpv4DestinationUnreachable(ns3::Icmpv4DestinationUnreachable const & arg0) [constructor]
    cls.add_constructor([param('ns3::Icmpv4DestinationUnreachable const &', 'arg0')])
    ## icmpv4.h (module 'internet'): ns3::Icmpv4DestinationUnreachable::Icmpv4DestinationUnreachable() [constructor]
    cls.add_constructor([])
    ## icmpv4.h (module 'internet'): void ns3::Icmpv4DestinationUnreachable::GetData(uint8_t * payload) const [member function]
    cls.add_method('GetData', 
                   'void', 
                   [param('uint8_t *', 'payload')], 
                   is_const=True)
    ## icmpv4.h (module 'internet'): ns3::Ipv4Header ns3::Icmpv4DestinationUnreachable::GetHeader() const [member function]
    cls.add_method('GetHeader', 
                   'ns3::Ipv4Header', 
                   [], 
                   is_const=True)
    ## icmpv4.h (module 'internet'): uint16_t ns3::Icmpv4DestinationUnreachable::GetNextHopMtu() const [member function]
    cls.add_method('GetNextHopMtu', 
                   'uint16_t', 
                   [], 
                   is_const=True)
    ## icmpv4.h (module 'internet'): static ns3::TypeId ns3::Icmpv4DestinationUnreachable::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## icmpv4.h (module 'internet'): void ns3::Icmpv4DestinationUnreachable::SetData(ns3::Ptr<const ns3::Packet> data) [member function]
    cls.add_method('SetData', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet const >', 'data')])
    ## icmpv4.h (module 'internet'): void ns3::Icmpv4DestinationUnreachable::SetHeader(ns3::Ipv4Header header) [member function]
    cls.add_method('SetHeader', 
                   'void', 
                   [param('ns3::Ipv4Header', 'header')])
    ## icmpv4.h (module 'internet'): void ns3::Icmpv4DestinationUnreachable::SetNextHopMtu(uint16_t mtu) [member function]
    cls.add_method('SetNextHopMtu', 
                   'void', 
                   [param('uint16_t', 'mtu')])
    ## icmpv4.h (module 'internet'): uint32_t ns3::Icmpv4DestinationUnreachable::Deserialize(ns3::Buffer::Iterator start) [member function]
    cls.add_method('Deserialize', 
                   'uint32_t', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   visibility='private', is_virtual=True)
    ## icmpv4.h (module 'internet'): ns3::TypeId ns3::Icmpv4DestinationUnreachable::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, visibility='private', is_virtual=True)
    ## icmpv4.h (module 'internet'): uint32_t ns3::Icmpv4DestinationUnreachable::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True, visibility='private', is_virtual=True)
    ## icmpv4.h (module 'internet'): void ns3::Icmpv4DestinationUnreachable::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True, visibility='private', is_virtual=True)
    ## icmpv4.h (module 'internet'): void ns3::Icmpv4DestinationUnreachable::Serialize(ns3::Buffer::Iterator start) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_const=True, visibility='private', is_virtual=True)
    return

def register_Ns3Icmpv4Echo_methods(root_module, cls):
    ## icmpv4.h (module 'internet'): ns3::Icmpv4Echo::Icmpv4Echo(ns3::Icmpv4Echo const & arg0) [constructor]
    cls.add_constructor([param('ns3::Icmpv4Echo const &', 'arg0')])
    ## icmpv4.h (module 'internet'): ns3::Icmpv4Echo::Icmpv4Echo() [constructor]
    cls.add_constructor([])
    ## icmpv4.h (module 'internet'): uint32_t ns3::Icmpv4Echo::Deserialize(ns3::Buffer::Iterator start) [member function]
    cls.add_method('Deserialize', 
                   'uint32_t', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_virtual=True)
    ## icmpv4.h (module 'internet'): uint32_t ns3::Icmpv4Echo::GetData(uint8_t * payload) const [member function]
    cls.add_method('GetData', 
                   'uint32_t', 
                   [param('uint8_t *', 'payload')], 
                   is_const=True)
    ## icmpv4.h (module 'internet'): uint32_t ns3::Icmpv4Echo::GetDataSize() const [member function]
    cls.add_method('GetDataSize', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## icmpv4.h (module 'internet'): uint16_t ns3::Icmpv4Echo::GetIdentifier() const [member function]
    cls.add_method('GetIdentifier', 
                   'uint16_t', 
                   [], 
                   is_const=True)
    ## icmpv4.h (module 'internet'): ns3::TypeId ns3::Icmpv4Echo::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## icmpv4.h (module 'internet'): uint16_t ns3::Icmpv4Echo::GetSequenceNumber() const [member function]
    cls.add_method('GetSequenceNumber', 
                   'uint16_t', 
                   [], 
                   is_const=True)
    ## icmpv4.h (module 'internet'): uint32_t ns3::Icmpv4Echo::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## icmpv4.h (module 'internet'): static ns3::TypeId ns3::Icmpv4Echo::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## icmpv4.h (module 'internet'): void ns3::Icmpv4Echo::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True, is_virtual=True)
    ## icmpv4.h (module 'internet'): void ns3::Icmpv4Echo::Serialize(ns3::Buffer::Iterator start) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_const=True, is_virtual=True)
    ## icmpv4.h (module 'internet'): void ns3::Icmpv4Echo::SetData(ns3::Ptr<const ns3::Packet> data) [member function]
    cls.add_method('SetData', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet const >', 'data')])
    ## icmpv4.h (module 'internet'): void ns3::Icmpv4Echo::SetIdentifier(uint16_t id) [member function]
    cls.add_method('SetIdentifier', 
                   'void', 
                   [param('uint16_t', 'id')])
    ## icmpv4.h (module 'internet'): void ns3::Icmpv4Echo::SetSequenceNumber(uint16_t seq) [member function]
    cls.add_method('SetSequenceNumber', 
                   'void', 
                   [param('uint16_t', 'seq')])
    return

def register_Ns3Icmpv4Header_methods(root_module, cls):
    ## icmpv4.h (module 'internet'): ns3::Icmpv4Header::Icmpv4Header(ns3::Icmpv4Header const & arg0) [constructor]
    cls.add_constructor([param('ns3::Icmpv4Header const &', 'arg0')])
    ## icmpv4.h (module 'internet'): ns3::Icmpv4Header::Icmpv4Header() [constructor]
    cls.add_constructor([])
    ## icmpv4.h (module 'internet'): uint32_t ns3::Icmpv4Header::Deserialize(ns3::Buffer::Iterator start) [member function]
    cls.add_method('Deserialize', 
                   'uint32_t', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_virtual=True)
    ## icmpv4.h (module 'internet'): void ns3::Icmpv4Header::EnableChecksum() [member function]
    cls.add_method('EnableChecksum', 
                   'void', 
                   [])
    ## icmpv4.h (module 'internet'): uint8_t ns3::Icmpv4Header::GetCode() const [member function]
    cls.add_method('GetCode', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## icmpv4.h (module 'internet'): ns3::TypeId ns3::Icmpv4Header::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## icmpv4.h (module 'internet'): uint32_t ns3::Icmpv4Header::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## icmpv4.h (module 'internet'): uint8_t ns3::Icmpv4Header::GetType() const [member function]
    cls.add_method('GetType', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## icmpv4.h (module 'internet'): static ns3::TypeId ns3::Icmpv4Header::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## icmpv4.h (module 'internet'): void ns3::Icmpv4Header::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True, is_virtual=True)
    ## icmpv4.h (module 'internet'): void ns3::Icmpv4Header::Serialize(ns3::Buffer::Iterator start) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_const=True, is_virtual=True)
    ## icmpv4.h (module 'internet'): void ns3::Icmpv4Header::SetCode(uint8_t code) [member function]
    cls.add_method('SetCode', 
                   'void', 
                   [param('uint8_t', 'code')])
    ## icmpv4.h (module 'internet'): void ns3::Icmpv4Header::SetType(uint8_t type) [member function]
    cls.add_method('SetType', 
                   'void', 
                   [param('uint8_t', 'type')])
    return

def register_Ns3Icmpv4TimeExceeded_methods(root_module, cls):
    ## icmpv4.h (module 'internet'): ns3::Icmpv4TimeExceeded::Icmpv4TimeExceeded(ns3::Icmpv4TimeExceeded const & arg0) [constructor]
    cls.add_constructor([param('ns3::Icmpv4TimeExceeded const &', 'arg0')])
    ## icmpv4.h (module 'internet'): ns3::Icmpv4TimeExceeded::Icmpv4TimeExceeded() [constructor]
    cls.add_constructor([])
    ## icmpv4.h (module 'internet'): uint32_t ns3::Icmpv4TimeExceeded::Deserialize(ns3::Buffer::Iterator start) [member function]
    cls.add_method('Deserialize', 
                   'uint32_t', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_virtual=True)
    ## icmpv4.h (module 'internet'): void ns3::Icmpv4TimeExceeded::GetData(uint8_t * payload) const [member function]
    cls.add_method('GetData', 
                   'void', 
                   [param('uint8_t *', 'payload')], 
                   is_const=True)
    ## icmpv4.h (module 'internet'): ns3::Ipv4Header ns3::Icmpv4TimeExceeded::GetHeader() const [member function]
    cls.add_method('GetHeader', 
                   'ns3::Ipv4Header', 
                   [], 
                   is_const=True)
    ## icmpv4.h (module 'internet'): ns3::TypeId ns3::Icmpv4TimeExceeded::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## icmpv4.h (module 'internet'): uint32_t ns3::Icmpv4TimeExceeded::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## icmpv4.h (module 'internet'): static ns3::TypeId ns3::Icmpv4TimeExceeded::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## icmpv4.h (module 'internet'): void ns3::Icmpv4TimeExceeded::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True, is_virtual=True)
    ## icmpv4.h (module 'internet'): void ns3::Icmpv4TimeExceeded::Serialize(ns3::Buffer::Iterator start) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_const=True, is_virtual=True)
    ## icmpv4.h (module 'internet'): void ns3::Icmpv4TimeExceeded::SetData(ns3::Ptr<const ns3::Packet> data) [member function]
    cls.add_method('SetData', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet const >', 'data')])
    ## icmpv4.h (module 'internet'): void ns3::Icmpv4TimeExceeded::SetHeader(ns3::Ipv4Header header) [member function]
    cls.add_method('SetHeader', 
                   'void', 
                   [param('ns3::Ipv4Header', 'header')])
    return

def register_Ns3Ipv4Header_methods(root_module, cls):
    ## ipv4-header.h (module 'internet'): ns3::Ipv4Header::Ipv4Header(ns3::Ipv4Header const & arg0) [constructor]
    cls.add_constructor([param('ns3::Ipv4Header const &', 'arg0')])
    ## ipv4-header.h (module 'internet'): ns3::Ipv4Header::Ipv4Header() [constructor]
    cls.add_constructor([])
    ## ipv4-header.h (module 'internet'): uint32_t ns3::Ipv4Header::Deserialize(ns3::Buffer::Iterator start) [member function]
    cls.add_method('Deserialize', 
                   'uint32_t', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_virtual=True)
    ## ipv4-header.h (module 'internet'): std::string ns3::Ipv4Header::DscpTypeToString(ns3::Ipv4Header::DscpType dscp) const [member function]
    cls.add_method('DscpTypeToString', 
                   'std::string', 
                   [param('ns3::Ipv4Header::DscpType', 'dscp')], 
                   is_const=True)
    ## ipv4-header.h (module 'internet'): std::string ns3::Ipv4Header::EcnTypeToString(ns3::Ipv4Header::EcnType ecn) const [member function]
    cls.add_method('EcnTypeToString', 
                   'std::string', 
                   [param('ns3::Ipv4Header::EcnType', 'ecn')], 
                   is_const=True)
    ## ipv4-header.h (module 'internet'): void ns3::Ipv4Header::EnableChecksum() [member function]
    cls.add_method('EnableChecksum', 
                   'void', 
                   [])
    ## ipv4-header.h (module 'internet'): ns3::Ipv4Address ns3::Ipv4Header::GetDestination() const [member function]
    cls.add_method('GetDestination', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## ipv4-header.h (module 'internet'): ns3::Ipv4Header::DscpType ns3::Ipv4Header::GetDscp() const [member function]
    cls.add_method('GetDscp', 
                   'ns3::Ipv4Header::DscpType', 
                   [], 
                   is_const=True)
    ## ipv4-header.h (module 'internet'): ns3::Ipv4Header::EcnType ns3::Ipv4Header::GetEcn() const [member function]
    cls.add_method('GetEcn', 
                   'ns3::Ipv4Header::EcnType', 
                   [], 
                   is_const=True)
    ## ipv4-header.h (module 'internet'): uint16_t ns3::Ipv4Header::GetFragmentOffset() const [member function]
    cls.add_method('GetFragmentOffset', 
                   'uint16_t', 
                   [], 
                   is_const=True)
    ## ipv4-header.h (module 'internet'): uint16_t ns3::Ipv4Header::GetIdentification() const [member function]
    cls.add_method('GetIdentification', 
                   'uint16_t', 
                   [], 
                   is_const=True)
    ## ipv4-header.h (module 'internet'): ns3::TypeId ns3::Ipv4Header::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## ipv4-header.h (module 'internet'): uint16_t ns3::Ipv4Header::GetPayloadSize() const [member function]
    cls.add_method('GetPayloadSize', 
                   'uint16_t', 
                   [], 
                   is_const=True)
    ## ipv4-header.h (module 'internet'): uint8_t ns3::Ipv4Header::GetProtocol() const [member function]
    cls.add_method('GetProtocol', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## ipv4-header.h (module 'internet'): uint32_t ns3::Ipv4Header::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## ipv4-header.h (module 'internet'): ns3::Ipv4Address ns3::Ipv4Header::GetSource() const [member function]
    cls.add_method('GetSource', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## ipv4-header.h (module 'internet'): uint8_t ns3::Ipv4Header::GetTos() const [member function]
    cls.add_method('GetTos', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## ipv4-header.h (module 'internet'): uint8_t ns3::Ipv4Header::GetTtl() const [member function]
    cls.add_method('GetTtl', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## ipv4-header.h (module 'internet'): static ns3::TypeId ns3::Ipv4Header::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## ipv4-header.h (module 'internet'): bool ns3::Ipv4Header::IsChecksumOk() const [member function]
    cls.add_method('IsChecksumOk', 
                   'bool', 
                   [], 
                   is_const=True)
    ## ipv4-header.h (module 'internet'): bool ns3::Ipv4Header::IsDontFragment() const [member function]
    cls.add_method('IsDontFragment', 
                   'bool', 
                   [], 
                   is_const=True)
    ## ipv4-header.h (module 'internet'): bool ns3::Ipv4Header::IsLastFragment() const [member function]
    cls.add_method('IsLastFragment', 
                   'bool', 
                   [], 
                   is_const=True)
    ## ipv4-header.h (module 'internet'): void ns3::Ipv4Header::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True, is_virtual=True)
    ## ipv4-header.h (module 'internet'): void ns3::Ipv4Header::Serialize(ns3::Buffer::Iterator start) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_const=True, is_virtual=True)
    ## ipv4-header.h (module 'internet'): void ns3::Ipv4Header::SetDestination(ns3::Ipv4Address destination) [member function]
    cls.add_method('SetDestination', 
                   'void', 
                   [param('ns3::Ipv4Address', 'destination')])
    ## ipv4-header.h (module 'internet'): void ns3::Ipv4Header::SetDontFragment() [member function]
    cls.add_method('SetDontFragment', 
                   'void', 
                   [])
    ## ipv4-header.h (module 'internet'): void ns3::Ipv4Header::SetDscp(ns3::Ipv4Header::DscpType dscp) [member function]
    cls.add_method('SetDscp', 
                   'void', 
                   [param('ns3::Ipv4Header::DscpType', 'dscp')])
    ## ipv4-header.h (module 'internet'): void ns3::Ipv4Header::SetEcn(ns3::Ipv4Header::EcnType ecn) [member function]
    cls.add_method('SetEcn', 
                   'void', 
                   [param('ns3::Ipv4Header::EcnType', 'ecn')])
    ## ipv4-header.h (module 'internet'): void ns3::Ipv4Header::SetFragmentOffset(uint16_t offsetBytes) [member function]
    cls.add_method('SetFragmentOffset', 
                   'void', 
                   [param('uint16_t', 'offsetBytes')])
    ## ipv4-header.h (module 'internet'): void ns3::Ipv4Header::SetIdentification(uint16_t identification) [member function]
    cls.add_method('SetIdentification', 
                   'void', 
                   [param('uint16_t', 'identification')])
    ## ipv4-header.h (module 'internet'): void ns3::Ipv4Header::SetLastFragment() [member function]
    cls.add_method('SetLastFragment', 
                   'void', 
                   [])
    ## ipv4-header.h (module 'internet'): void ns3::Ipv4Header::SetMayFragment() [member function]
    cls.add_method('SetMayFragment', 
                   'void', 
                   [])
    ## ipv4-header.h (module 'internet'): void ns3::Ipv4Header::SetMoreFragments() [member function]
    cls.add_method('SetMoreFragments', 
                   'void', 
                   [])
    ## ipv4-header.h (module 'internet'): void ns3::Ipv4Header::SetPayloadSize(uint16_t size) [member function]
    cls.add_method('SetPayloadSize', 
                   'void', 
                   [param('uint16_t', 'size')])
    ## ipv4-header.h (module 'internet'): void ns3::Ipv4Header::SetProtocol(uint8_t num) [member function]
    cls.add_method('SetProtocol', 
                   'void', 
                   [param('uint8_t', 'num')])
    ## ipv4-header.h (module 'internet'): void ns3::Ipv4Header::SetSource(ns3::Ipv4Address source) [member function]
    cls.add_method('SetSource', 
                   'void', 
                   [param('ns3::Ipv4Address', 'source')])
    ## ipv4-header.h (module 'internet'): void ns3::Ipv4Header::SetTos(uint8_t tos) [member function]
    cls.add_method('SetTos', 
                   'void', 
                   [param('uint8_t', 'tos')])
    ## ipv4-header.h (module 'internet'): void ns3::Ipv4Header::SetTtl(uint8_t ttl) [member function]
    cls.add_method('SetTtl', 
                   'void', 
                   [param('uint8_t', 'ttl')])
    return

def register_Ns3Ipv6Header_methods(root_module, cls):
    ## ipv6-header.h (module 'internet'): ns3::Ipv6Header::Ipv6Header(ns3::Ipv6Header const & arg0) [constructor]
    cls.add_constructor([param('ns3::Ipv6Header const &', 'arg0')])
    ## ipv6-header.h (module 'internet'): ns3::Ipv6Header::Ipv6Header() [constructor]
    cls.add_constructor([])
    ## ipv6-header.h (module 'internet'): uint32_t ns3::Ipv6Header::Deserialize(ns3::Buffer::Iterator start) [member function]
    cls.add_method('Deserialize', 
                   'uint32_t', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_virtual=True)
    ## ipv6-header.h (module 'internet'): std::string ns3::Ipv6Header::DscpTypeToString(ns3::Ipv6Header::DscpType dscp) const [member function]
    cls.add_method('DscpTypeToString', 
                   'std::string', 
                   [param('ns3::Ipv6Header::DscpType', 'dscp')], 
                   is_const=True)
    ## ipv6-header.h (module 'internet'): std::string ns3::Ipv6Header::EcnTypeToString(ns3::Ipv6Header::EcnType ecn) const [member function]
    cls.add_method('EcnTypeToString', 
                   'std::string', 
                   [param('ns3::Ipv6Header::EcnType', 'ecn')], 
                   is_const=True)
    ## ipv6-header.h (module 'internet'): ns3::Ipv6Address ns3::Ipv6Header::GetDestinationAddress() const [member function]
    cls.add_method('GetDestinationAddress', 
                   'ns3::Ipv6Address', 
                   [], 
                   is_const=True)
    ## ipv6-header.h (module 'internet'): ns3::Ipv6Header::DscpType ns3::Ipv6Header::GetDscp() const [member function]
    cls.add_method('GetDscp', 
                   'ns3::Ipv6Header::DscpType', 
                   [], 
                   is_const=True)
    ## ipv6-header.h (module 'internet'): ns3::Ipv6Header::EcnType ns3::Ipv6Header::GetEcn() const [member function]
    cls.add_method('GetEcn', 
                   'ns3::Ipv6Header::EcnType', 
                   [], 
                   is_const=True)
    ## ipv6-header.h (module 'internet'): uint32_t ns3::Ipv6Header::GetFlowLabel() const [member function]
    cls.add_method('GetFlowLabel', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## ipv6-header.h (module 'internet'): uint8_t ns3::Ipv6Header::GetHopLimit() const [member function]
    cls.add_method('GetHopLimit', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## ipv6-header.h (module 'internet'): ns3::TypeId ns3::Ipv6Header::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## ipv6-header.h (module 'internet'): uint8_t ns3::Ipv6Header::GetNextHeader() const [member function]
    cls.add_method('GetNextHeader', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## ipv6-header.h (module 'internet'): uint16_t ns3::Ipv6Header::GetPayloadLength() const [member function]
    cls.add_method('GetPayloadLength', 
                   'uint16_t', 
                   [], 
                   is_const=True)
    ## ipv6-header.h (module 'internet'): uint32_t ns3::Ipv6Header::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## ipv6-header.h (module 'internet'): ns3::Ipv6Address ns3::Ipv6Header::GetSourceAddress() const [member function]
    cls.add_method('GetSourceAddress', 
                   'ns3::Ipv6Address', 
                   [], 
                   is_const=True)
    ## ipv6-header.h (module 'internet'): uint8_t ns3::Ipv6Header::GetTrafficClass() const [member function]
    cls.add_method('GetTrafficClass', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## ipv6-header.h (module 'internet'): static ns3::TypeId ns3::Ipv6Header::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## ipv6-header.h (module 'internet'): void ns3::Ipv6Header::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True, is_virtual=True)
    ## ipv6-header.h (module 'internet'): void ns3::Ipv6Header::Serialize(ns3::Buffer::Iterator start) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_const=True, is_virtual=True)
    ## ipv6-header.h (module 'internet'): void ns3::Ipv6Header::SetDestinationAddress(ns3::Ipv6Address dst) [member function]
    cls.add_method('SetDestinationAddress', 
                   'void', 
                   [param('ns3::Ipv6Address', 'dst')])
    ## ipv6-header.h (module 'internet'): void ns3::Ipv6Header::SetDscp(ns3::Ipv6Header::DscpType dscp) [member function]
    cls.add_method('SetDscp', 
                   'void', 
                   [param('ns3::Ipv6Header::DscpType', 'dscp')])
    ## ipv6-header.h (module 'internet'): void ns3::Ipv6Header::SetEcn(ns3::Ipv6Header::EcnType ecn) [member function]
    cls.add_method('SetEcn', 
                   'void', 
                   [param('ns3::Ipv6Header::EcnType', 'ecn')])
    ## ipv6-header.h (module 'internet'): void ns3::Ipv6Header::SetFlowLabel(uint32_t flow) [member function]
    cls.add_method('SetFlowLabel', 
                   'void', 
                   [param('uint32_t', 'flow')])
    ## ipv6-header.h (module 'internet'): void ns3::Ipv6Header::SetHopLimit(uint8_t limit) [member function]
    cls.add_method('SetHopLimit', 
                   'void', 
                   [param('uint8_t', 'limit')])
    ## ipv6-header.h (module 'internet'): void ns3::Ipv6Header::SetNextHeader(uint8_t next) [member function]
    cls.add_method('SetNextHeader', 
                   'void', 
                   [param('uint8_t', 'next')])
    ## ipv6-header.h (module 'internet'): void ns3::Ipv6Header::SetPayloadLength(uint16_t len) [member function]
    cls.add_method('SetPayloadLength', 
                   'void', 
                   [param('uint16_t', 'len')])
    ## ipv6-header.h (module 'internet'): void ns3::Ipv6Header::SetSourceAddress(ns3::Ipv6Address src) [member function]
    cls.add_method('SetSourceAddress', 
                   'void', 
                   [param('ns3::Ipv6Address', 'src')])
    ## ipv6-header.h (module 'internet'): void ns3::Ipv6Header::SetTrafficClass(uint8_t traffic) [member function]
    cls.add_method('SetTrafficClass', 
                   'void', 
                   [param('uint8_t', 'traffic')])
    return

def register_Ns3Object_methods(root_module, cls):
    ## object.h (module 'core'): ns3::Object::Object() [constructor]
    cls.add_constructor([])
    ## object.h (module 'core'): void ns3::Object::AggregateObject(ns3::Ptr<ns3::Object> other) [member function]
    cls.add_method('AggregateObject', 
                   'void', 
                   [param('ns3::Ptr< ns3::Object >', 'other')])
    ## object.h (module 'core'): void ns3::Object::Dispose() [member function]
    cls.add_method('Dispose', 
                   'void', 
                   [])
    ## object.h (module 'core'): ns3::Object::AggregateIterator ns3::Object::GetAggregateIterator() const [member function]
    cls.add_method('GetAggregateIterator', 
                   'ns3::Object::AggregateIterator', 
                   [], 
                   is_const=True)
    ## object.h (module 'core'): ns3::TypeId ns3::Object::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## object.h (module 'core'): static ns3::TypeId ns3::Object::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## object.h (module 'core'): void ns3::Object::Initialize() [member function]
    cls.add_method('Initialize', 
                   'void', 
                   [])
    ## object.h (module 'core'): bool ns3::Object::IsInitialized() const [member function]
    cls.add_method('IsInitialized', 
                   'bool', 
                   [], 
                   is_const=True)
    ## object.h (module 'core'): ns3::Object::Object(ns3::Object const & o) [constructor]
    cls.add_constructor([param('ns3::Object const &', 'o')], 
                        visibility='protected')
    ## object.h (module 'core'): void ns3::Object::DoDispose() [member function]
    cls.add_method('DoDispose', 
                   'void', 
                   [], 
                   visibility='protected', is_virtual=True)
    ## object.h (module 'core'): void ns3::Object::DoInitialize() [member function]
    cls.add_method('DoInitialize', 
                   'void', 
                   [], 
                   visibility='protected', is_virtual=True)
    ## object.h (module 'core'): void ns3::Object::NotifyNewAggregate() [member function]
    cls.add_method('NotifyNewAggregate', 
                   'void', 
                   [], 
                   visibility='protected', is_virtual=True)
    return

def register_Ns3ObjectAggregateIterator_methods(root_module, cls):
    ## object.h (module 'core'): ns3::Object::AggregateIterator::AggregateIterator(ns3::Object::AggregateIterator const & arg0) [constructor]
    cls.add_constructor([param('ns3::Object::AggregateIterator const &', 'arg0')])
    ## object.h (module 'core'): ns3::Object::AggregateIterator::AggregateIterator() [constructor]
    cls.add_constructor([])
    ## object.h (module 'core'): bool ns3::Object::AggregateIterator::HasNext() const [member function]
    cls.add_method('HasNext', 
                   'bool', 
                   [], 
                   is_const=True)
    ## object.h (module 'core'): ns3::Ptr<const ns3::Object> ns3::Object::AggregateIterator::Next() [member function]
    cls.add_method('Next', 
                   'ns3::Ptr< ns3::Object const >', 
                   [])
    return

def register_Ns3RandomVariableStream_methods(root_module, cls):
    ## random-variable-stream.h (module 'core'): static ns3::TypeId ns3::RandomVariableStream::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## random-variable-stream.h (module 'core'): ns3::RandomVariableStream::RandomVariableStream() [constructor]
    cls.add_constructor([])
    ## random-variable-stream.h (module 'core'): void ns3::RandomVariableStream::SetStream(int64_t stream) [member function]
    cls.add_method('SetStream', 
                   'void', 
                   [param('int64_t', 'stream')])
    ## random-variable-stream.h (module 'core'): int64_t ns3::RandomVariableStream::GetStream() const [member function]
    cls.add_method('GetStream', 
                   'int64_t', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): void ns3::RandomVariableStream::SetAntithetic(bool isAntithetic) [member function]
    cls.add_method('SetAntithetic', 
                   'void', 
                   [param('bool', 'isAntithetic')])
    ## random-variable-stream.h (module 'core'): bool ns3::RandomVariableStream::IsAntithetic() const [member function]
    cls.add_method('IsAntithetic', 
                   'bool', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::RandomVariableStream::GetValue() [member function]
    cls.add_method('GetValue', 
                   'double', 
                   [], 
                   is_pure_virtual=True, is_virtual=True)
    ## random-variable-stream.h (module 'core'): uint32_t ns3::RandomVariableStream::GetInteger() [member function]
    cls.add_method('GetInteger', 
                   'uint32_t', 
                   [], 
                   is_pure_virtual=True, is_virtual=True)
    ## random-variable-stream.h (module 'core'): ns3::RngStream * ns3::RandomVariableStream::Peek() const [member function]
    cls.add_method('Peek', 
                   'ns3::RngStream *', 
                   [], 
                   is_const=True, visibility='protected')
    return

def register_Ns3SequentialRandomVariable_methods(root_module, cls):
    ## random-variable-stream.h (module 'core'): static ns3::TypeId ns3::SequentialRandomVariable::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## random-variable-stream.h (module 'core'): ns3::SequentialRandomVariable::SequentialRandomVariable() [constructor]
    cls.add_constructor([])
    ## random-variable-stream.h (module 'core'): double ns3::SequentialRandomVariable::GetMin() const [member function]
    cls.add_method('GetMin', 
                   'double', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::SequentialRandomVariable::GetMax() const [member function]
    cls.add_method('GetMax', 
                   'double', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): ns3::Ptr<ns3::RandomVariableStream> ns3::SequentialRandomVariable::GetIncrement() const [member function]
    cls.add_method('GetIncrement', 
                   'ns3::Ptr< ns3::RandomVariableStream >', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): uint32_t ns3::SequentialRandomVariable::GetConsecutive() const [member function]
    cls.add_method('GetConsecutive', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::SequentialRandomVariable::GetValue() [member function]
    cls.add_method('GetValue', 
                   'double', 
                   [], 
                   is_virtual=True)
    ## random-variable-stream.h (module 'core'): uint32_t ns3::SequentialRandomVariable::GetInteger() [member function]
    cls.add_method('GetInteger', 
                   'uint32_t', 
                   [], 
                   is_virtual=True)
    return

def register_Ns3SimpleRefCount__Ns3AttributeAccessor_Ns3Empty_Ns3DefaultDeleter__lt__ns3AttributeAccessor__gt___methods(root_module, cls):
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::AttributeAccessor, ns3::empty, ns3::DefaultDeleter<ns3::AttributeAccessor> >::SimpleRefCount() [constructor]
    cls.add_constructor([])
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::AttributeAccessor, ns3::empty, ns3::DefaultDeleter<ns3::AttributeAccessor> >::SimpleRefCount(ns3::SimpleRefCount<ns3::AttributeAccessor, ns3::empty, ns3::DefaultDeleter<ns3::AttributeAccessor> > const & o) [constructor]
    cls.add_constructor([param('ns3::SimpleRefCount< ns3::AttributeAccessor, ns3::empty, ns3::DefaultDeleter< ns3::AttributeAccessor > > const &', 'o')])
    return

def register_Ns3SimpleRefCount__Ns3AttributeChecker_Ns3Empty_Ns3DefaultDeleter__lt__ns3AttributeChecker__gt___methods(root_module, cls):
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::AttributeChecker, ns3::empty, ns3::DefaultDeleter<ns3::AttributeChecker> >::SimpleRefCount() [constructor]
    cls.add_constructor([])
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::AttributeChecker, ns3::empty, ns3::DefaultDeleter<ns3::AttributeChecker> >::SimpleRefCount(ns3::SimpleRefCount<ns3::AttributeChecker, ns3::empty, ns3::DefaultDeleter<ns3::AttributeChecker> > const & o) [constructor]
    cls.add_constructor([param('ns3::SimpleRefCount< ns3::AttributeChecker, ns3::empty, ns3::DefaultDeleter< ns3::AttributeChecker > > const &', 'o')])
    return

def register_Ns3SimpleRefCount__Ns3AttributeValue_Ns3Empty_Ns3DefaultDeleter__lt__ns3AttributeValue__gt___methods(root_module, cls):
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::AttributeValue, ns3::empty, ns3::DefaultDeleter<ns3::AttributeValue> >::SimpleRefCount() [constructor]
    cls.add_constructor([])
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::AttributeValue, ns3::empty, ns3::DefaultDeleter<ns3::AttributeValue> >::SimpleRefCount(ns3::SimpleRefCount<ns3::AttributeValue, ns3::empty, ns3::DefaultDeleter<ns3::AttributeValue> > const & o) [constructor]
    cls.add_constructor([param('ns3::SimpleRefCount< ns3::AttributeValue, ns3::empty, ns3::DefaultDeleter< ns3::AttributeValue > > const &', 'o')])
    return

def register_Ns3SimpleRefCount__Ns3CallbackImplBase_Ns3Empty_Ns3DefaultDeleter__lt__ns3CallbackImplBase__gt___methods(root_module, cls):
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::CallbackImplBase, ns3::empty, ns3::DefaultDeleter<ns3::CallbackImplBase> >::SimpleRefCount() [constructor]
    cls.add_constructor([])
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::CallbackImplBase, ns3::empty, ns3::DefaultDeleter<ns3::CallbackImplBase> >::SimpleRefCount(ns3::SimpleRefCount<ns3::CallbackImplBase, ns3::empty, ns3::DefaultDeleter<ns3::CallbackImplBase> > const & o) [constructor]
    cls.add_constructor([param('ns3::SimpleRefCount< ns3::CallbackImplBase, ns3::empty, ns3::DefaultDeleter< ns3::CallbackImplBase > > const &', 'o')])
    return

def register_Ns3SimpleRefCount__Ns3EventImpl_Ns3Empty_Ns3DefaultDeleter__lt__ns3EventImpl__gt___methods(root_module, cls):
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::EventImpl, ns3::empty, ns3::DefaultDeleter<ns3::EventImpl> >::SimpleRefCount() [constructor]
    cls.add_constructor([])
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::EventImpl, ns3::empty, ns3::DefaultDeleter<ns3::EventImpl> >::SimpleRefCount(ns3::SimpleRefCount<ns3::EventImpl, ns3::empty, ns3::DefaultDeleter<ns3::EventImpl> > const & o) [constructor]
    cls.add_constructor([param('ns3::SimpleRefCount< ns3::EventImpl, ns3::empty, ns3::DefaultDeleter< ns3::EventImpl > > const &', 'o')])
    return

def register_Ns3SimpleRefCount__Ns3HashImplementation_Ns3Empty_Ns3DefaultDeleter__lt__ns3HashImplementation__gt___methods(root_module, cls):
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::Hash::Implementation, ns3::empty, ns3::DefaultDeleter<ns3::Hash::Implementation> >::SimpleRefCount() [constructor]
    cls.add_constructor([])
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::Hash::Implementation, ns3::empty, ns3::DefaultDeleter<ns3::Hash::Implementation> >::SimpleRefCount(ns3::SimpleRefCount<ns3::Hash::Implementation, ns3::empty, ns3::DefaultDeleter<ns3::Hash::Implementation> > const & o) [constructor]
    cls.add_constructor([param('ns3::SimpleRefCount< ns3::Hash::Implementation, ns3::empty, ns3::DefaultDeleter< ns3::Hash::Implementation > > const &', 'o')])
    return

def register_Ns3SimpleRefCount__Ns3Ipv4MulticastRoute_Ns3Empty_Ns3DefaultDeleter__lt__ns3Ipv4MulticastRoute__gt___methods(root_module, cls):
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::Ipv4MulticastRoute, ns3::empty, ns3::DefaultDeleter<ns3::Ipv4MulticastRoute> >::SimpleRefCount() [constructor]
    cls.add_constructor([])
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::Ipv4MulticastRoute, ns3::empty, ns3::DefaultDeleter<ns3::Ipv4MulticastRoute> >::SimpleRefCount(ns3::SimpleRefCount<ns3::Ipv4MulticastRoute, ns3::empty, ns3::DefaultDeleter<ns3::Ipv4MulticastRoute> > const & o) [constructor]
    cls.add_constructor([param('ns3::SimpleRefCount< ns3::Ipv4MulticastRoute, ns3::empty, ns3::DefaultDeleter< ns3::Ipv4MulticastRoute > > const &', 'o')])
    return

def register_Ns3SimpleRefCount__Ns3Ipv4Route_Ns3Empty_Ns3DefaultDeleter__lt__ns3Ipv4Route__gt___methods(root_module, cls):
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::Ipv4Route, ns3::empty, ns3::DefaultDeleter<ns3::Ipv4Route> >::SimpleRefCount() [constructor]
    cls.add_constructor([])
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::Ipv4Route, ns3::empty, ns3::DefaultDeleter<ns3::Ipv4Route> >::SimpleRefCount(ns3::SimpleRefCount<ns3::Ipv4Route, ns3::empty, ns3::DefaultDeleter<ns3::Ipv4Route> > const & o) [constructor]
    cls.add_constructor([param('ns3::SimpleRefCount< ns3::Ipv4Route, ns3::empty, ns3::DefaultDeleter< ns3::Ipv4Route > > const &', 'o')])
    return

def register_Ns3SimpleRefCount__Ns3NixVector_Ns3Empty_Ns3DefaultDeleter__lt__ns3NixVector__gt___methods(root_module, cls):
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::NixVector, ns3::empty, ns3::DefaultDeleter<ns3::NixVector> >::SimpleRefCount() [constructor]
    cls.add_constructor([])
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::NixVector, ns3::empty, ns3::DefaultDeleter<ns3::NixVector> >::SimpleRefCount(ns3::SimpleRefCount<ns3::NixVector, ns3::empty, ns3::DefaultDeleter<ns3::NixVector> > const & o) [constructor]
    cls.add_constructor([param('ns3::SimpleRefCount< ns3::NixVector, ns3::empty, ns3::DefaultDeleter< ns3::NixVector > > const &', 'o')])
    return

def register_Ns3SimpleRefCount__Ns3OutputStreamWrapper_Ns3Empty_Ns3DefaultDeleter__lt__ns3OutputStreamWrapper__gt___methods(root_module, cls):
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::OutputStreamWrapper, ns3::empty, ns3::DefaultDeleter<ns3::OutputStreamWrapper> >::SimpleRefCount() [constructor]
    cls.add_constructor([])
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::OutputStreamWrapper, ns3::empty, ns3::DefaultDeleter<ns3::OutputStreamWrapper> >::SimpleRefCount(ns3::SimpleRefCount<ns3::OutputStreamWrapper, ns3::empty, ns3::DefaultDeleter<ns3::OutputStreamWrapper> > const & o) [constructor]
    cls.add_constructor([param('ns3::SimpleRefCount< ns3::OutputStreamWrapper, ns3::empty, ns3::DefaultDeleter< ns3::OutputStreamWrapper > > const &', 'o')])
    return

def register_Ns3SimpleRefCount__Ns3Packet_Ns3Empty_Ns3DefaultDeleter__lt__ns3Packet__gt___methods(root_module, cls):
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::Packet, ns3::empty, ns3::DefaultDeleter<ns3::Packet> >::SimpleRefCount() [constructor]
    cls.add_constructor([])
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::Packet, ns3::empty, ns3::DefaultDeleter<ns3::Packet> >::SimpleRefCount(ns3::SimpleRefCount<ns3::Packet, ns3::empty, ns3::DefaultDeleter<ns3::Packet> > const & o) [constructor]
    cls.add_constructor([param('ns3::SimpleRefCount< ns3::Packet, ns3::empty, ns3::DefaultDeleter< ns3::Packet > > const &', 'o')])
    return

def register_Ns3SimpleRefCount__Ns3TraceSourceAccessor_Ns3Empty_Ns3DefaultDeleter__lt__ns3TraceSourceAccessor__gt___methods(root_module, cls):
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::TraceSourceAccessor, ns3::empty, ns3::DefaultDeleter<ns3::TraceSourceAccessor> >::SimpleRefCount() [constructor]
    cls.add_constructor([])
    ## simple-ref-count.h (module 'core'): ns3::SimpleRefCount<ns3::TraceSourceAccessor, ns3::empty, ns3::DefaultDeleter<ns3::TraceSourceAccessor> >::SimpleRefCount(ns3::SimpleRefCount<ns3::TraceSourceAccessor, ns3::empty, ns3::DefaultDeleter<ns3::TraceSourceAccessor> > const & o) [constructor]
    cls.add_constructor([param('ns3::SimpleRefCount< ns3::TraceSourceAccessor, ns3::empty, ns3::DefaultDeleter< ns3::TraceSourceAccessor > > const &', 'o')])
    return

def register_Ns3Socket_methods(root_module, cls):
    ## socket.h (module 'network'): ns3::Socket::Socket(ns3::Socket const & arg0) [constructor]
    cls.add_constructor([param('ns3::Socket const &', 'arg0')])
    ## socket.h (module 'network'): ns3::Socket::Socket() [constructor]
    cls.add_constructor([])
    ## socket.h (module 'network'): int ns3::Socket::Bind(ns3::Address const & address) [member function]
    cls.add_method('Bind', 
                   'int', 
                   [param('ns3::Address const &', 'address')], 
                   is_pure_virtual=True, is_virtual=True)
    ## socket.h (module 'network'): int ns3::Socket::Bind() [member function]
    cls.add_method('Bind', 
                   'int', 
                   [], 
                   is_pure_virtual=True, is_virtual=True)
    ## socket.h (module 'network'): int ns3::Socket::Bind6() [member function]
    cls.add_method('Bind6', 
                   'int', 
                   [], 
                   is_pure_virtual=True, is_virtual=True)
    ## socket.h (module 'network'): void ns3::Socket::BindToNetDevice(ns3::Ptr<ns3::NetDevice> netdevice) [member function]
    cls.add_method('BindToNetDevice', 
                   'void', 
                   [param('ns3::Ptr< ns3::NetDevice >', 'netdevice')], 
                   is_virtual=True)
    ## socket.h (module 'network'): int ns3::Socket::Close() [member function]
    cls.add_method('Close', 
                   'int', 
                   [], 
                   is_pure_virtual=True, is_virtual=True)
    ## socket.h (module 'network'): int ns3::Socket::Connect(ns3::Address const & address) [member function]
    cls.add_method('Connect', 
                   'int', 
                   [param('ns3::Address const &', 'address')], 
                   is_pure_virtual=True, is_virtual=True)
    ## socket.h (module 'network'): static ns3::Ptr<ns3::Socket> ns3::Socket::CreateSocket(ns3::Ptr<ns3::Node> node, ns3::TypeId tid) [member function]
    cls.add_method('CreateSocket', 
                   'ns3::Ptr< ns3::Socket >', 
                   [param('ns3::Ptr< ns3::Node >', 'node'), param('ns3::TypeId', 'tid')], 
                   is_static=True)
    ## socket.h (module 'network'): bool ns3::Socket::GetAllowBroadcast() const [member function]
    cls.add_method('GetAllowBroadcast', 
                   'bool', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## socket.h (module 'network'): ns3::Ptr<ns3::NetDevice> ns3::Socket::GetBoundNetDevice() [member function]
    cls.add_method('GetBoundNetDevice', 
                   'ns3::Ptr< ns3::NetDevice >', 
                   [])
    ## socket.h (module 'network'): ns3::Socket::SocketErrno ns3::Socket::GetErrno() const [member function]
    cls.add_method('GetErrno', 
                   'ns3::Socket::SocketErrno', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## socket.h (module 'network'): uint8_t ns3::Socket::GetIpTos() const [member function]
    cls.add_method('GetIpTos', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## socket.h (module 'network'): uint8_t ns3::Socket::GetIpTtl() const [member function]
    cls.add_method('GetIpTtl', 
                   'uint8_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## socket.h (module 'network'): uint8_t ns3::Socket::GetIpv6HopLimit() const [member function]
    cls.add_method('GetIpv6HopLimit', 
                   'uint8_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## socket.h (module 'network'): uint8_t ns3::Socket::GetIpv6Tclass() const [member function]
    cls.add_method('GetIpv6Tclass', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## socket.h (module 'network'): ns3::Ptr<ns3::Node> ns3::Socket::GetNode() const [member function]
    cls.add_method('GetNode', 
                   'ns3::Ptr< ns3::Node >', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## socket.h (module 'network'): int ns3::Socket::GetPeerName(ns3::Address & address) const [member function]
    cls.add_method('GetPeerName', 
                   'int', 
                   [param('ns3::Address &', 'address')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## socket.h (module 'network'): uint8_t ns3::Socket::GetPriority() const [member function]
    cls.add_method('GetPriority', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## socket.h (module 'network'): uint32_t ns3::Socket::GetRxAvailable() const [member function]
    cls.add_method('GetRxAvailable', 
                   'uint32_t', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## socket.h (module 'network'): int ns3::Socket::GetSockName(ns3::Address & address) const [member function]
    cls.add_method('GetSockName', 
                   'int', 
                   [param('ns3::Address &', 'address')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## socket.h (module 'network'): ns3::Socket::SocketType ns3::Socket::GetSocketType() const [member function]
    cls.add_method('GetSocketType', 
                   'ns3::Socket::SocketType', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## socket.h (module 'network'): uint32_t ns3::Socket::GetTxAvailable() const [member function]
    cls.add_method('GetTxAvailable', 
                   'uint32_t', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## socket.h (module 'network'): static ns3::TypeId ns3::Socket::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## socket.h (module 'network'): static uint8_t ns3::Socket::IpTos2Priority(uint8_t ipTos) [member function]
    cls.add_method('IpTos2Priority', 
                   'uint8_t', 
                   [param('uint8_t', 'ipTos')], 
                   is_static=True)
    ## socket.h (module 'network'): void ns3::Socket::Ipv6JoinGroup(ns3::Ipv6Address address, ns3::Socket::Ipv6MulticastFilterMode filterMode, std::vector<ns3::Ipv6Address, std::allocator<ns3::Ipv6Address> > sourceAddresses) [member function]
    cls.add_method('Ipv6JoinGroup', 
                   'void', 
                   [param('ns3::Ipv6Address', 'address'), param('ns3::Socket::Ipv6MulticastFilterMode', 'filterMode'), param('std::vector< ns3::Ipv6Address >', 'sourceAddresses')], 
                   is_virtual=True)
    ## socket.h (module 'network'): void ns3::Socket::Ipv6JoinGroup(ns3::Ipv6Address address) [member function]
    cls.add_method('Ipv6JoinGroup', 
                   'void', 
                   [param('ns3::Ipv6Address', 'address')], 
                   is_virtual=True)
    ## socket.h (module 'network'): void ns3::Socket::Ipv6LeaveGroup() [member function]
    cls.add_method('Ipv6LeaveGroup', 
                   'void', 
                   [], 
                   is_virtual=True)
    ## socket.h (module 'network'): bool ns3::Socket::IsIpRecvTos() const [member function]
    cls.add_method('IsIpRecvTos', 
                   'bool', 
                   [], 
                   is_const=True)
    ## socket.h (module 'network'): bool ns3::Socket::IsIpRecvTtl() const [member function]
    cls.add_method('IsIpRecvTtl', 
                   'bool', 
                   [], 
                   is_const=True)
    ## socket.h (module 'network'): bool ns3::Socket::IsIpv6RecvHopLimit() const [member function]
    cls.add_method('IsIpv6RecvHopLimit', 
                   'bool', 
                   [], 
                   is_const=True)
    ## socket.h (module 'network'): bool ns3::Socket::IsIpv6RecvTclass() const [member function]
    cls.add_method('IsIpv6RecvTclass', 
                   'bool', 
                   [], 
                   is_const=True)
    ## socket.h (module 'network'): bool ns3::Socket::IsRecvPktInfo() const [member function]
    cls.add_method('IsRecvPktInfo', 
                   'bool', 
                   [], 
                   is_const=True)
    ## socket.h (module 'network'): int ns3::Socket::Listen() [member function]
    cls.add_method('Listen', 
                   'int', 
                   [], 
                   is_pure_virtual=True, is_virtual=True)
    ## socket.h (module 'network'): ns3::Ptr<ns3::Packet> ns3::Socket::Recv(uint32_t maxSize, uint32_t flags) [member function]
    cls.add_method('Recv', 
                   'ns3::Ptr< ns3::Packet >', 
                   [param('uint32_t', 'maxSize'), param('uint32_t', 'flags')], 
                   is_pure_virtual=True, is_virtual=True)
    ## socket.h (module 'network'): ns3::Ptr<ns3::Packet> ns3::Socket::Recv() [member function]
    cls.add_method('Recv', 
                   'ns3::Ptr< ns3::Packet >', 
                   [])
    ## socket.h (module 'network'): int ns3::Socket::Recv(uint8_t * buf, uint32_t size, uint32_t flags) [member function]
    cls.add_method('Recv', 
                   'int', 
                   [param('uint8_t *', 'buf'), param('uint32_t', 'size'), param('uint32_t', 'flags')])
    ## socket.h (module 'network'): ns3::Ptr<ns3::Packet> ns3::Socket::RecvFrom(uint32_t maxSize, uint32_t flags, ns3::Address & fromAddress) [member function]
    cls.add_method('RecvFrom', 
                   'ns3::Ptr< ns3::Packet >', 
                   [param('uint32_t', 'maxSize'), param('uint32_t', 'flags'), param('ns3::Address &', 'fromAddress')], 
                   is_pure_virtual=True, is_virtual=True)
    ## socket.h (module 'network'): ns3::Ptr<ns3::Packet> ns3::Socket::RecvFrom(ns3::Address & fromAddress) [member function]
    cls.add_method('RecvFrom', 
                   'ns3::Ptr< ns3::Packet >', 
                   [param('ns3::Address &', 'fromAddress')])
    ## socket.h (module 'network'): int ns3::Socket::RecvFrom(uint8_t * buf, uint32_t size, uint32_t flags, ns3::Address & fromAddress) [member function]
    cls.add_method('RecvFrom', 
                   'int', 
                   [param('uint8_t *', 'buf'), param('uint32_t', 'size'), param('uint32_t', 'flags'), param('ns3::Address &', 'fromAddress')])
    ## socket.h (module 'network'): int ns3::Socket::Send(ns3::Ptr<ns3::Packet> p, uint32_t flags) [member function]
    cls.add_method('Send', 
                   'int', 
                   [param('ns3::Ptr< ns3::Packet >', 'p'), param('uint32_t', 'flags')], 
                   is_pure_virtual=True, is_virtual=True)
    ## socket.h (module 'network'): int ns3::Socket::Send(ns3::Ptr<ns3::Packet> p) [member function]
    cls.add_method('Send', 
                   'int', 
                   [param('ns3::Ptr< ns3::Packet >', 'p')])
    ## socket.h (module 'network'): int ns3::Socket::Send(uint8_t const * buf, uint32_t size, uint32_t flags) [member function]
    cls.add_method('Send', 
                   'int', 
                   [param('uint8_t const *', 'buf'), param('uint32_t', 'size'), param('uint32_t', 'flags')])
    ## socket.h (module 'network'): int ns3::Socket::SendTo(ns3::Ptr<ns3::Packet> p, uint32_t flags, ns3::Address const & toAddress) [member function]
    cls.add_method('SendTo', 
                   'int', 
                   [param('ns3::Ptr< ns3::Packet >', 'p'), param('uint32_t', 'flags'), param('ns3::Address const &', 'toAddress')], 
                   is_pure_virtual=True, is_virtual=True)
    ## socket.h (module 'network'): int ns3::Socket::SendTo(uint8_t const * buf, uint32_t size, uint32_t flags, ns3::Address const & address) [member function]
    cls.add_method('SendTo', 
                   'int', 
                   [param('uint8_t const *', 'buf'), param('uint32_t', 'size'), param('uint32_t', 'flags'), param('ns3::Address const &', 'address')])
    ## socket.h (module 'network'): void ns3::Socket::SetAcceptCallback(ns3::Callback<bool, ns3::Ptr<ns3::Socket>, const ns3::Address &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> connectionRequest, ns3::Callback<void, ns3::Ptr<ns3::Socket>, const ns3::Address &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> newConnectionCreated) [member function]
    cls.add_method('SetAcceptCallback', 
                   'void', 
                   [param('ns3::Callback< bool, ns3::Ptr< ns3::Socket >, ns3::Address const &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'connectionRequest'), param('ns3::Callback< void, ns3::Ptr< ns3::Socket >, ns3::Address const &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'newConnectionCreated')])
    ## socket.h (module 'network'): bool ns3::Socket::SetAllowBroadcast(bool allowBroadcast) [member function]
    cls.add_method('SetAllowBroadcast', 
                   'bool', 
                   [param('bool', 'allowBroadcast')], 
                   is_pure_virtual=True, is_virtual=True)
    ## socket.h (module 'network'): void ns3::Socket::SetCloseCallbacks(ns3::Callback<void, ns3::Ptr<ns3::Socket>, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> normalClose, ns3::Callback<void, ns3::Ptr<ns3::Socket>, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> errorClose) [member function]
    cls.add_method('SetCloseCallbacks', 
                   'void', 
                   [param('ns3::Callback< void, ns3::Ptr< ns3::Socket >, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'normalClose'), param('ns3::Callback< void, ns3::Ptr< ns3::Socket >, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'errorClose')])
    ## socket.h (module 'network'): void ns3::Socket::SetConnectCallback(ns3::Callback<void, ns3::Ptr<ns3::Socket>, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> connectionSucceeded, ns3::Callback<void, ns3::Ptr<ns3::Socket>, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> connectionFailed) [member function]
    cls.add_method('SetConnectCallback', 
                   'void', 
                   [param('ns3::Callback< void, ns3::Ptr< ns3::Socket >, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'connectionSucceeded'), param('ns3::Callback< void, ns3::Ptr< ns3::Socket >, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'connectionFailed')])
    ## socket.h (module 'network'): void ns3::Socket::SetDataSentCallback(ns3::Callback<void, ns3::Ptr<ns3::Socket>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> dataSent) [member function]
    cls.add_method('SetDataSentCallback', 
                   'void', 
                   [param('ns3::Callback< void, ns3::Ptr< ns3::Socket >, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'dataSent')])
    ## socket.h (module 'network'): void ns3::Socket::SetIpRecvTos(bool ipv4RecvTos) [member function]
    cls.add_method('SetIpRecvTos', 
                   'void', 
                   [param('bool', 'ipv4RecvTos')])
    ## socket.h (module 'network'): void ns3::Socket::SetIpRecvTtl(bool ipv4RecvTtl) [member function]
    cls.add_method('SetIpRecvTtl', 
                   'void', 
                   [param('bool', 'ipv4RecvTtl')])
    ## socket.h (module 'network'): void ns3::Socket::SetIpTos(uint8_t ipTos) [member function]
    cls.add_method('SetIpTos', 
                   'void', 
                   [param('uint8_t', 'ipTos')])
    ## socket.h (module 'network'): void ns3::Socket::SetIpTtl(uint8_t ipTtl) [member function]
    cls.add_method('SetIpTtl', 
                   'void', 
                   [param('uint8_t', 'ipTtl')], 
                   is_virtual=True)
    ## socket.h (module 'network'): void ns3::Socket::SetIpv6HopLimit(uint8_t ipHopLimit) [member function]
    cls.add_method('SetIpv6HopLimit', 
                   'void', 
                   [param('uint8_t', 'ipHopLimit')], 
                   is_virtual=True)
    ## socket.h (module 'network'): void ns3::Socket::SetIpv6RecvHopLimit(bool ipv6RecvHopLimit) [member function]
    cls.add_method('SetIpv6RecvHopLimit', 
                   'void', 
                   [param('bool', 'ipv6RecvHopLimit')])
    ## socket.h (module 'network'): void ns3::Socket::SetIpv6RecvTclass(bool ipv6RecvTclass) [member function]
    cls.add_method('SetIpv6RecvTclass', 
                   'void', 
                   [param('bool', 'ipv6RecvTclass')])
    ## socket.h (module 'network'): void ns3::Socket::SetIpv6Tclass(int ipTclass) [member function]
    cls.add_method('SetIpv6Tclass', 
                   'void', 
                   [param('int', 'ipTclass')])
    ## socket.h (module 'network'): void ns3::Socket::SetPriority(uint8_t priority) [member function]
    cls.add_method('SetPriority', 
                   'void', 
                   [param('uint8_t', 'priority')])
    ## socket.h (module 'network'): void ns3::Socket::SetRecvCallback(ns3::Callback<void, ns3::Ptr<ns3::Socket>, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> arg0) [member function]
    cls.add_method('SetRecvCallback', 
                   'void', 
                   [param('ns3::Callback< void, ns3::Ptr< ns3::Socket >, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'arg0')])
    ## socket.h (module 'network'): void ns3::Socket::SetRecvPktInfo(bool flag) [member function]
    cls.add_method('SetRecvPktInfo', 
                   'void', 
                   [param('bool', 'flag')])
    ## socket.h (module 'network'): void ns3::Socket::SetSendCallback(ns3::Callback<void, ns3::Ptr<ns3::Socket>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> sendCb) [member function]
    cls.add_method('SetSendCallback', 
                   'void', 
                   [param('ns3::Callback< void, ns3::Ptr< ns3::Socket >, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'sendCb')])
    ## socket.h (module 'network'): int ns3::Socket::ShutdownRecv() [member function]
    cls.add_method('ShutdownRecv', 
                   'int', 
                   [], 
                   is_pure_virtual=True, is_virtual=True)
    ## socket.h (module 'network'): int ns3::Socket::ShutdownSend() [member function]
    cls.add_method('ShutdownSend', 
                   'int', 
                   [], 
                   is_pure_virtual=True, is_virtual=True)
    ## socket.h (module 'network'): void ns3::Socket::DoDispose() [member function]
    cls.add_method('DoDispose', 
                   'void', 
                   [], 
                   visibility='protected', is_virtual=True)
    ## socket.h (module 'network'): bool ns3::Socket::IsManualIpTtl() const [member function]
    cls.add_method('IsManualIpTtl', 
                   'bool', 
                   [], 
                   is_const=True, visibility='protected')
    ## socket.h (module 'network'): bool ns3::Socket::IsManualIpv6HopLimit() const [member function]
    cls.add_method('IsManualIpv6HopLimit', 
                   'bool', 
                   [], 
                   is_const=True, visibility='protected')
    ## socket.h (module 'network'): bool ns3::Socket::IsManualIpv6Tclass() const [member function]
    cls.add_method('IsManualIpv6Tclass', 
                   'bool', 
                   [], 
                   is_const=True, visibility='protected')
    ## socket.h (module 'network'): void ns3::Socket::NotifyConnectionFailed() [member function]
    cls.add_method('NotifyConnectionFailed', 
                   'void', 
                   [], 
                   visibility='protected')
    ## socket.h (module 'network'): bool ns3::Socket::NotifyConnectionRequest(ns3::Address const & from) [member function]
    cls.add_method('NotifyConnectionRequest', 
                   'bool', 
                   [param('ns3::Address const &', 'from')], 
                   visibility='protected')
    ## socket.h (module 'network'): void ns3::Socket::NotifyConnectionSucceeded() [member function]
    cls.add_method('NotifyConnectionSucceeded', 
                   'void', 
                   [], 
                   visibility='protected')
    ## socket.h (module 'network'): void ns3::Socket::NotifyDataRecv() [member function]
    cls.add_method('NotifyDataRecv', 
                   'void', 
                   [], 
                   visibility='protected')
    ## socket.h (module 'network'): void ns3::Socket::NotifyDataSent(uint32_t size) [member function]
    cls.add_method('NotifyDataSent', 
                   'void', 
                   [param('uint32_t', 'size')], 
                   visibility='protected')
    ## socket.h (module 'network'): void ns3::Socket::NotifyErrorClose() [member function]
    cls.add_method('NotifyErrorClose', 
                   'void', 
                   [], 
                   visibility='protected')
    ## socket.h (module 'network'): void ns3::Socket::NotifyNewConnectionCreated(ns3::Ptr<ns3::Socket> socket, ns3::Address const & from) [member function]
    cls.add_method('NotifyNewConnectionCreated', 
                   'void', 
                   [param('ns3::Ptr< ns3::Socket >', 'socket'), param('ns3::Address const &', 'from')], 
                   visibility='protected')
    ## socket.h (module 'network'): void ns3::Socket::NotifyNormalClose() [member function]
    cls.add_method('NotifyNormalClose', 
                   'void', 
                   [], 
                   visibility='protected')
    ## socket.h (module 'network'): void ns3::Socket::NotifySend(uint32_t spaceAvailable) [member function]
    cls.add_method('NotifySend', 
                   'void', 
                   [param('uint32_t', 'spaceAvailable')], 
                   visibility='protected')
    return

def register_Ns3SocketIpTosTag_methods(root_module, cls):
    ## socket.h (module 'network'): ns3::SocketIpTosTag::SocketIpTosTag(ns3::SocketIpTosTag const & arg0) [constructor]
    cls.add_constructor([param('ns3::SocketIpTosTag const &', 'arg0')])
    ## socket.h (module 'network'): ns3::SocketIpTosTag::SocketIpTosTag() [constructor]
    cls.add_constructor([])
    ## socket.h (module 'network'): void ns3::SocketIpTosTag::Deserialize(ns3::TagBuffer i) [member function]
    cls.add_method('Deserialize', 
                   'void', 
                   [param('ns3::TagBuffer', 'i')], 
                   is_virtual=True)
    ## socket.h (module 'network'): ns3::TypeId ns3::SocketIpTosTag::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## socket.h (module 'network'): uint32_t ns3::SocketIpTosTag::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## socket.h (module 'network'): uint8_t ns3::SocketIpTosTag::GetTos() const [member function]
    cls.add_method('GetTos', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## socket.h (module 'network'): static ns3::TypeId ns3::SocketIpTosTag::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## socket.h (module 'network'): void ns3::SocketIpTosTag::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True, is_virtual=True)
    ## socket.h (module 'network'): void ns3::SocketIpTosTag::Serialize(ns3::TagBuffer i) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::TagBuffer', 'i')], 
                   is_const=True, is_virtual=True)
    ## socket.h (module 'network'): void ns3::SocketIpTosTag::SetTos(uint8_t tos) [member function]
    cls.add_method('SetTos', 
                   'void', 
                   [param('uint8_t', 'tos')])
    return

def register_Ns3SocketIpTtlTag_methods(root_module, cls):
    ## socket.h (module 'network'): ns3::SocketIpTtlTag::SocketIpTtlTag(ns3::SocketIpTtlTag const & arg0) [constructor]
    cls.add_constructor([param('ns3::SocketIpTtlTag const &', 'arg0')])
    ## socket.h (module 'network'): ns3::SocketIpTtlTag::SocketIpTtlTag() [constructor]
    cls.add_constructor([])
    ## socket.h (module 'network'): void ns3::SocketIpTtlTag::Deserialize(ns3::TagBuffer i) [member function]
    cls.add_method('Deserialize', 
                   'void', 
                   [param('ns3::TagBuffer', 'i')], 
                   is_virtual=True)
    ## socket.h (module 'network'): ns3::TypeId ns3::SocketIpTtlTag::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## socket.h (module 'network'): uint32_t ns3::SocketIpTtlTag::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## socket.h (module 'network'): uint8_t ns3::SocketIpTtlTag::GetTtl() const [member function]
    cls.add_method('GetTtl', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## socket.h (module 'network'): static ns3::TypeId ns3::SocketIpTtlTag::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## socket.h (module 'network'): void ns3::SocketIpTtlTag::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True, is_virtual=True)
    ## socket.h (module 'network'): void ns3::SocketIpTtlTag::Serialize(ns3::TagBuffer i) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::TagBuffer', 'i')], 
                   is_const=True, is_virtual=True)
    ## socket.h (module 'network'): void ns3::SocketIpTtlTag::SetTtl(uint8_t ttl) [member function]
    cls.add_method('SetTtl', 
                   'void', 
                   [param('uint8_t', 'ttl')])
    return

def register_Ns3SocketIpv6HopLimitTag_methods(root_module, cls):
    ## socket.h (module 'network'): ns3::SocketIpv6HopLimitTag::SocketIpv6HopLimitTag(ns3::SocketIpv6HopLimitTag const & arg0) [constructor]
    cls.add_constructor([param('ns3::SocketIpv6HopLimitTag const &', 'arg0')])
    ## socket.h (module 'network'): ns3::SocketIpv6HopLimitTag::SocketIpv6HopLimitTag() [constructor]
    cls.add_constructor([])
    ## socket.h (module 'network'): void ns3::SocketIpv6HopLimitTag::Deserialize(ns3::TagBuffer i) [member function]
    cls.add_method('Deserialize', 
                   'void', 
                   [param('ns3::TagBuffer', 'i')], 
                   is_virtual=True)
    ## socket.h (module 'network'): uint8_t ns3::SocketIpv6HopLimitTag::GetHopLimit() const [member function]
    cls.add_method('GetHopLimit', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## socket.h (module 'network'): ns3::TypeId ns3::SocketIpv6HopLimitTag::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## socket.h (module 'network'): uint32_t ns3::SocketIpv6HopLimitTag::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## socket.h (module 'network'): static ns3::TypeId ns3::SocketIpv6HopLimitTag::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## socket.h (module 'network'): void ns3::SocketIpv6HopLimitTag::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True, is_virtual=True)
    ## socket.h (module 'network'): void ns3::SocketIpv6HopLimitTag::Serialize(ns3::TagBuffer i) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::TagBuffer', 'i')], 
                   is_const=True, is_virtual=True)
    ## socket.h (module 'network'): void ns3::SocketIpv6HopLimitTag::SetHopLimit(uint8_t hopLimit) [member function]
    cls.add_method('SetHopLimit', 
                   'void', 
                   [param('uint8_t', 'hopLimit')])
    return

def register_Ns3SocketIpv6TclassTag_methods(root_module, cls):
    ## socket.h (module 'network'): ns3::SocketIpv6TclassTag::SocketIpv6TclassTag(ns3::SocketIpv6TclassTag const & arg0) [constructor]
    cls.add_constructor([param('ns3::SocketIpv6TclassTag const &', 'arg0')])
    ## socket.h (module 'network'): ns3::SocketIpv6TclassTag::SocketIpv6TclassTag() [constructor]
    cls.add_constructor([])
    ## socket.h (module 'network'): void ns3::SocketIpv6TclassTag::Deserialize(ns3::TagBuffer i) [member function]
    cls.add_method('Deserialize', 
                   'void', 
                   [param('ns3::TagBuffer', 'i')], 
                   is_virtual=True)
    ## socket.h (module 'network'): ns3::TypeId ns3::SocketIpv6TclassTag::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## socket.h (module 'network'): uint32_t ns3::SocketIpv6TclassTag::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## socket.h (module 'network'): uint8_t ns3::SocketIpv6TclassTag::GetTclass() const [member function]
    cls.add_method('GetTclass', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## socket.h (module 'network'): static ns3::TypeId ns3::SocketIpv6TclassTag::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## socket.h (module 'network'): void ns3::SocketIpv6TclassTag::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True, is_virtual=True)
    ## socket.h (module 'network'): void ns3::SocketIpv6TclassTag::Serialize(ns3::TagBuffer i) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::TagBuffer', 'i')], 
                   is_const=True, is_virtual=True)
    ## socket.h (module 'network'): void ns3::SocketIpv6TclassTag::SetTclass(uint8_t tclass) [member function]
    cls.add_method('SetTclass', 
                   'void', 
                   [param('uint8_t', 'tclass')])
    return

def register_Ns3SocketPriorityTag_methods(root_module, cls):
    ## socket.h (module 'network'): ns3::SocketPriorityTag::SocketPriorityTag(ns3::SocketPriorityTag const & arg0) [constructor]
    cls.add_constructor([param('ns3::SocketPriorityTag const &', 'arg0')])
    ## socket.h (module 'network'): ns3::SocketPriorityTag::SocketPriorityTag() [constructor]
    cls.add_constructor([])
    ## socket.h (module 'network'): void ns3::SocketPriorityTag::Deserialize(ns3::TagBuffer i) [member function]
    cls.add_method('Deserialize', 
                   'void', 
                   [param('ns3::TagBuffer', 'i')], 
                   is_virtual=True)
    ## socket.h (module 'network'): ns3::TypeId ns3::SocketPriorityTag::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## socket.h (module 'network'): uint8_t ns3::SocketPriorityTag::GetPriority() const [member function]
    cls.add_method('GetPriority', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## socket.h (module 'network'): uint32_t ns3::SocketPriorityTag::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## socket.h (module 'network'): static ns3::TypeId ns3::SocketPriorityTag::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## socket.h (module 'network'): void ns3::SocketPriorityTag::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True, is_virtual=True)
    ## socket.h (module 'network'): void ns3::SocketPriorityTag::Serialize(ns3::TagBuffer i) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::TagBuffer', 'i')], 
                   is_const=True, is_virtual=True)
    ## socket.h (module 'network'): void ns3::SocketPriorityTag::SetPriority(uint8_t priority) [member function]
    cls.add_method('SetPriority', 
                   'void', 
                   [param('uint8_t', 'priority')])
    return

def register_Ns3SocketSetDontFragmentTag_methods(root_module, cls):
    ## socket.h (module 'network'): ns3::SocketSetDontFragmentTag::SocketSetDontFragmentTag(ns3::SocketSetDontFragmentTag const & arg0) [constructor]
    cls.add_constructor([param('ns3::SocketSetDontFragmentTag const &', 'arg0')])
    ## socket.h (module 'network'): ns3::SocketSetDontFragmentTag::SocketSetDontFragmentTag() [constructor]
    cls.add_constructor([])
    ## socket.h (module 'network'): void ns3::SocketSetDontFragmentTag::Deserialize(ns3::TagBuffer i) [member function]
    cls.add_method('Deserialize', 
                   'void', 
                   [param('ns3::TagBuffer', 'i')], 
                   is_virtual=True)
    ## socket.h (module 'network'): void ns3::SocketSetDontFragmentTag::Disable() [member function]
    cls.add_method('Disable', 
                   'void', 
                   [])
    ## socket.h (module 'network'): void ns3::SocketSetDontFragmentTag::Enable() [member function]
    cls.add_method('Enable', 
                   'void', 
                   [])
    ## socket.h (module 'network'): ns3::TypeId ns3::SocketSetDontFragmentTag::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## socket.h (module 'network'): uint32_t ns3::SocketSetDontFragmentTag::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## socket.h (module 'network'): static ns3::TypeId ns3::SocketSetDontFragmentTag::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## socket.h (module 'network'): bool ns3::SocketSetDontFragmentTag::IsEnabled() const [member function]
    cls.add_method('IsEnabled', 
                   'bool', 
                   [], 
                   is_const=True)
    ## socket.h (module 'network'): void ns3::SocketSetDontFragmentTag::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True, is_virtual=True)
    ## socket.h (module 'network'): void ns3::SocketSetDontFragmentTag::Serialize(ns3::TagBuffer i) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::TagBuffer', 'i')], 
                   is_const=True, is_virtual=True)
    return

def register_Ns3Time_methods(root_module, cls):
    cls.add_binary_comparison_operator('==')
    cls.add_binary_comparison_operator('!=')
    cls.add_binary_comparison_operator('<=')
    cls.add_binary_comparison_operator('>=')
    cls.add_binary_comparison_operator('<')
    cls.add_binary_comparison_operator('>')
    cls.add_binary_numeric_operator('+', root_module['ns3::Time'], root_module['ns3::Time'], param('ns3::Time const &', u'right'))
    cls.add_binary_numeric_operator('-', root_module['ns3::Time'], root_module['ns3::Time'], param('ns3::Time const &', u'right'))
    cls.add_binary_numeric_operator('*', root_module['ns3::Time'], root_module['ns3::Time'], param('int64_t const &', u'right'))
    cls.add_binary_numeric_operator('/', root_module['ns3::Time'], root_module['ns3::Time'], param('int64_t const &', u'right'))
    cls.add_inplace_numeric_operator('+=', param('ns3::Time const &', u'right'))
    cls.add_inplace_numeric_operator('-=', param('ns3::Time const &', u'right'))
    cls.add_output_stream_operator()
    ## nstime.h (module 'core'): ns3::Time::Time() [constructor]
    cls.add_constructor([])
    ## nstime.h (module 'core'): ns3::Time::Time(ns3::Time const & o) [constructor]
    cls.add_constructor([param('ns3::Time const &', 'o')])
    ## nstime.h (module 'core'): ns3::Time::Time(double v) [constructor]
    cls.add_constructor([param('double', 'v')])
    ## nstime.h (module 'core'): ns3::Time::Time(int v) [constructor]
    cls.add_constructor([param('int', 'v')])
    ## nstime.h (module 'core'): ns3::Time::Time(long int v) [constructor]
    cls.add_constructor([param('long int', 'v')])
    ## nstime.h (module 'core'): ns3::Time::Time(long long int v) [constructor]
    cls.add_constructor([param('long long int', 'v')])
    ## nstime.h (module 'core'): ns3::Time::Time(unsigned int v) [constructor]
    cls.add_constructor([param('unsigned int', 'v')])
    ## nstime.h (module 'core'): ns3::Time::Time(long unsigned int v) [constructor]
    cls.add_constructor([param('long unsigned int', 'v')])
    ## nstime.h (module 'core'): ns3::Time::Time(long long unsigned int v) [constructor]
    cls.add_constructor([param('long long unsigned int', 'v')])
    ## nstime.h (module 'core'): ns3::Time::Time(ns3::int64x64_t const & v) [constructor]
    cls.add_constructor([param('ns3::int64x64_t const &', 'v')])
    ## nstime.h (module 'core'): ns3::Time::Time(std::string const & s) [constructor]
    cls.add_constructor([param('std::string const &', 's')])
    ## nstime.h (module 'core'): ns3::TimeWithUnit ns3::Time::As(ns3::Time::Unit const unit) const [member function]
    cls.add_method('As', 
                   'ns3::TimeWithUnit', 
                   [param('ns3::Time::Unit const', 'unit')], 
                   is_const=True)
    ## nstime.h (module 'core'): int ns3::Time::Compare(ns3::Time const & o) const [member function]
    cls.add_method('Compare', 
                   'int', 
                   [param('ns3::Time const &', 'o')], 
                   is_const=True)
    ## nstime.h (module 'core'): static ns3::Time ns3::Time::From(ns3::int64x64_t const & value) [member function]
    cls.add_method('From', 
                   'ns3::Time', 
                   [param('ns3::int64x64_t const &', 'value')], 
                   is_static=True)
    ## nstime.h (module 'core'): static ns3::Time ns3::Time::From(ns3::int64x64_t const & value, ns3::Time::Unit unit) [member function]
    cls.add_method('From', 
                   'ns3::Time', 
                   [param('ns3::int64x64_t const &', 'value'), param('ns3::Time::Unit', 'unit')], 
                   is_static=True)
    ## nstime.h (module 'core'): static ns3::Time ns3::Time::FromDouble(double value, ns3::Time::Unit unit) [member function]
    cls.add_method('FromDouble', 
                   'ns3::Time', 
                   [param('double', 'value'), param('ns3::Time::Unit', 'unit')], 
                   is_static=True)
    ## nstime.h (module 'core'): static ns3::Time ns3::Time::FromInteger(uint64_t value, ns3::Time::Unit unit) [member function]
    cls.add_method('FromInteger', 
                   'ns3::Time', 
                   [param('uint64_t', 'value'), param('ns3::Time::Unit', 'unit')], 
                   is_static=True)
    ## nstime.h (module 'core'): double ns3::Time::GetDays() const [member function]
    cls.add_method('GetDays', 
                   'double', 
                   [], 
                   is_const=True)
    ## nstime.h (module 'core'): double ns3::Time::GetDouble() const [member function]
    cls.add_method('GetDouble', 
                   'double', 
                   [], 
                   is_const=True)
    ## nstime.h (module 'core'): int64_t ns3::Time::GetFemtoSeconds() const [member function]
    cls.add_method('GetFemtoSeconds', 
                   'int64_t', 
                   [], 
                   is_const=True)
    ## nstime.h (module 'core'): double ns3::Time::GetHours() const [member function]
    cls.add_method('GetHours', 
                   'double', 
                   [], 
                   is_const=True)
    ## nstime.h (module 'core'): int64_t ns3::Time::GetInteger() const [member function]
    cls.add_method('GetInteger', 
                   'int64_t', 
                   [], 
                   is_const=True)
    ## nstime.h (module 'core'): int64_t ns3::Time::GetMicroSeconds() const [member function]
    cls.add_method('GetMicroSeconds', 
                   'int64_t', 
                   [], 
                   is_const=True)
    ## nstime.h (module 'core'): int64_t ns3::Time::GetMilliSeconds() const [member function]
    cls.add_method('GetMilliSeconds', 
                   'int64_t', 
                   [], 
                   is_const=True)
    ## nstime.h (module 'core'): double ns3::Time::GetMinutes() const [member function]
    cls.add_method('GetMinutes', 
                   'double', 
                   [], 
                   is_const=True)
    ## nstime.h (module 'core'): int64_t ns3::Time::GetNanoSeconds() const [member function]
    cls.add_method('GetNanoSeconds', 
                   'int64_t', 
                   [], 
                   is_const=True)
    ## nstime.h (module 'core'): int64_t ns3::Time::GetPicoSeconds() const [member function]
    cls.add_method('GetPicoSeconds', 
                   'int64_t', 
                   [], 
                   is_const=True)
    ## nstime.h (module 'core'): static ns3::Time::Unit ns3::Time::GetResolution() [member function]
    cls.add_method('GetResolution', 
                   'ns3::Time::Unit', 
                   [], 
                   is_static=True)
    ## nstime.h (module 'core'): double ns3::Time::GetSeconds() const [member function]
    cls.add_method('GetSeconds', 
                   'double', 
                   [], 
                   is_const=True)
    ## nstime.h (module 'core'): int64_t ns3::Time::GetTimeStep() const [member function]
    cls.add_method('GetTimeStep', 
                   'int64_t', 
                   [], 
                   is_const=True)
    ## nstime.h (module 'core'): double ns3::Time::GetYears() const [member function]
    cls.add_method('GetYears', 
                   'double', 
                   [], 
                   is_const=True)
    ## nstime.h (module 'core'): bool ns3::Time::IsNegative() const [member function]
    cls.add_method('IsNegative', 
                   'bool', 
                   [], 
                   is_const=True)
    ## nstime.h (module 'core'): bool ns3::Time::IsPositive() const [member function]
    cls.add_method('IsPositive', 
                   'bool', 
                   [], 
                   is_const=True)
    ## nstime.h (module 'core'): bool ns3::Time::IsStrictlyNegative() const [member function]
    cls.add_method('IsStrictlyNegative', 
                   'bool', 
                   [], 
                   is_const=True)
    ## nstime.h (module 'core'): bool ns3::Time::IsStrictlyPositive() const [member function]
    cls.add_method('IsStrictlyPositive', 
                   'bool', 
                   [], 
                   is_const=True)
    ## nstime.h (module 'core'): bool ns3::Time::IsZero() const [member function]
    cls.add_method('IsZero', 
                   'bool', 
                   [], 
                   is_const=True)
    ## nstime.h (module 'core'): static ns3::Time ns3::Time::Max() [member function]
    cls.add_method('Max', 
                   'ns3::Time', 
                   [], 
                   is_static=True)
    ## nstime.h (module 'core'): static ns3::Time ns3::Time::Min() [member function]
    cls.add_method('Min', 
                   'ns3::Time', 
                   [], 
                   is_static=True)
    ## nstime.h (module 'core'): static void ns3::Time::SetResolution(ns3::Time::Unit resolution) [member function]
    cls.add_method('SetResolution', 
                   'void', 
                   [param('ns3::Time::Unit', 'resolution')], 
                   is_static=True)
    ## nstime.h (module 'core'): static bool ns3::Time::StaticInit() [member function]
    cls.add_method('StaticInit', 
                   'bool', 
                   [], 
                   is_static=True)
    ## nstime.h (module 'core'): ns3::int64x64_t ns3::Time::To(ns3::Time::Unit unit) const [member function]
    cls.add_method('To', 
                   'ns3::int64x64_t', 
                   [param('ns3::Time::Unit', 'unit')], 
                   is_const=True)
    ## nstime.h (module 'core'): double ns3::Time::ToDouble(ns3::Time::Unit unit) const [member function]
    cls.add_method('ToDouble', 
                   'double', 
                   [param('ns3::Time::Unit', 'unit')], 
                   is_const=True)
    ## nstime.h (module 'core'): int64_t ns3::Time::ToInteger(ns3::Time::Unit unit) const [member function]
    cls.add_method('ToInteger', 
                   'int64_t', 
                   [param('ns3::Time::Unit', 'unit')], 
                   is_const=True)
    return

def register_Ns3TraceSourceAccessor_methods(root_module, cls):
    ## trace-source-accessor.h (module 'core'): ns3::TraceSourceAccessor::TraceSourceAccessor(ns3::TraceSourceAccessor const & arg0) [constructor]
    cls.add_constructor([param('ns3::TraceSourceAccessor const &', 'arg0')])
    ## trace-source-accessor.h (module 'core'): ns3::TraceSourceAccessor::TraceSourceAccessor() [constructor]
    cls.add_constructor([])
    ## trace-source-accessor.h (module 'core'): bool ns3::TraceSourceAccessor::Connect(ns3::ObjectBase * obj, std::string context, ns3::CallbackBase const & cb) const [member function]
    cls.add_method('Connect', 
                   'bool', 
                   [param('ns3::ObjectBase *', 'obj', transfer_ownership=False), param('std::string', 'context'), param('ns3::CallbackBase const &', 'cb')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## trace-source-accessor.h (module 'core'): bool ns3::TraceSourceAccessor::ConnectWithoutContext(ns3::ObjectBase * obj, ns3::CallbackBase const & cb) const [member function]
    cls.add_method('ConnectWithoutContext', 
                   'bool', 
                   [param('ns3::ObjectBase *', 'obj', transfer_ownership=False), param('ns3::CallbackBase const &', 'cb')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## trace-source-accessor.h (module 'core'): bool ns3::TraceSourceAccessor::Disconnect(ns3::ObjectBase * obj, std::string context, ns3::CallbackBase const & cb) const [member function]
    cls.add_method('Disconnect', 
                   'bool', 
                   [param('ns3::ObjectBase *', 'obj', transfer_ownership=False), param('std::string', 'context'), param('ns3::CallbackBase const &', 'cb')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## trace-source-accessor.h (module 'core'): bool ns3::TraceSourceAccessor::DisconnectWithoutContext(ns3::ObjectBase * obj, ns3::CallbackBase const & cb) const [member function]
    cls.add_method('DisconnectWithoutContext', 
                   'bool', 
                   [param('ns3::ObjectBase *', 'obj', transfer_ownership=False), param('ns3::CallbackBase const &', 'cb')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    return

def register_Ns3Trailer_methods(root_module, cls):
    cls.add_output_stream_operator()
    ## trailer.h (module 'network'): ns3::Trailer::Trailer() [constructor]
    cls.add_constructor([])
    ## trailer.h (module 'network'): ns3::Trailer::Trailer(ns3::Trailer const & arg0) [constructor]
    cls.add_constructor([param('ns3::Trailer const &', 'arg0')])
    ## trailer.h (module 'network'): uint32_t ns3::Trailer::Deserialize(ns3::Buffer::Iterator end) [member function]
    cls.add_method('Deserialize', 
                   'uint32_t', 
                   [param('ns3::Buffer::Iterator', 'end')], 
                   is_pure_virtual=True, is_virtual=True)
    ## trailer.h (module 'network'): uint32_t ns3::Trailer::Deserialize(ns3::Buffer::Iterator start, ns3::Buffer::Iterator end) [member function]
    cls.add_method('Deserialize', 
                   'uint32_t', 
                   [param('ns3::Buffer::Iterator', 'start'), param('ns3::Buffer::Iterator', 'end')], 
                   is_virtual=True)
    ## trailer.h (module 'network'): uint32_t ns3::Trailer::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## trailer.h (module 'network'): static ns3::TypeId ns3::Trailer::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## trailer.h (module 'network'): void ns3::Trailer::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## trailer.h (module 'network'): void ns3::Trailer::Serialize(ns3::Buffer::Iterator start) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    return

def register_Ns3TriangularRandomVariable_methods(root_module, cls):
    ## random-variable-stream.h (module 'core'): static ns3::TypeId ns3::TriangularRandomVariable::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## random-variable-stream.h (module 'core'): ns3::TriangularRandomVariable::TriangularRandomVariable() [constructor]
    cls.add_constructor([])
    ## random-variable-stream.h (module 'core'): double ns3::TriangularRandomVariable::GetMean() const [member function]
    cls.add_method('GetMean', 
                   'double', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::TriangularRandomVariable::GetMin() const [member function]
    cls.add_method('GetMin', 
                   'double', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::TriangularRandomVariable::GetMax() const [member function]
    cls.add_method('GetMax', 
                   'double', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::TriangularRandomVariable::GetValue(double mean, double min, double max) [member function]
    cls.add_method('GetValue', 
                   'double', 
                   [param('double', 'mean'), param('double', 'min'), param('double', 'max')])
    ## random-variable-stream.h (module 'core'): uint32_t ns3::TriangularRandomVariable::GetInteger(uint32_t mean, uint32_t min, uint32_t max) [member function]
    cls.add_method('GetInteger', 
                   'uint32_t', 
                   [param('uint32_t', 'mean'), param('uint32_t', 'min'), param('uint32_t', 'max')])
    ## random-variable-stream.h (module 'core'): double ns3::TriangularRandomVariable::GetValue() [member function]
    cls.add_method('GetValue', 
                   'double', 
                   [], 
                   is_virtual=True)
    ## random-variable-stream.h (module 'core'): uint32_t ns3::TriangularRandomVariable::GetInteger() [member function]
    cls.add_method('GetInteger', 
                   'uint32_t', 
                   [], 
                   is_virtual=True)
    return

def register_Ns3UniformRandomVariable_methods(root_module, cls):
    ## random-variable-stream.h (module 'core'): static ns3::TypeId ns3::UniformRandomVariable::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## random-variable-stream.h (module 'core'): ns3::UniformRandomVariable::UniformRandomVariable() [constructor]
    cls.add_constructor([])
    ## random-variable-stream.h (module 'core'): double ns3::UniformRandomVariable::GetMin() const [member function]
    cls.add_method('GetMin', 
                   'double', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::UniformRandomVariable::GetMax() const [member function]
    cls.add_method('GetMax', 
                   'double', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::UniformRandomVariable::GetValue(double min, double max) [member function]
    cls.add_method('GetValue', 
                   'double', 
                   [param('double', 'min'), param('double', 'max')])
    ## random-variable-stream.h (module 'core'): uint32_t ns3::UniformRandomVariable::GetInteger(uint32_t min, uint32_t max) [member function]
    cls.add_method('GetInteger', 
                   'uint32_t', 
                   [param('uint32_t', 'min'), param('uint32_t', 'max')])
    ## random-variable-stream.h (module 'core'): double ns3::UniformRandomVariable::GetValue() [member function]
    cls.add_method('GetValue', 
                   'double', 
                   [], 
                   is_virtual=True)
    ## random-variable-stream.h (module 'core'): uint32_t ns3::UniformRandomVariable::GetInteger() [member function]
    cls.add_method('GetInteger', 
                   'uint32_t', 
                   [], 
                   is_virtual=True)
    return

def register_Ns3WeibullRandomVariable_methods(root_module, cls):
    ## random-variable-stream.h (module 'core'): static ns3::TypeId ns3::WeibullRandomVariable::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## random-variable-stream.h (module 'core'): ns3::WeibullRandomVariable::WeibullRandomVariable() [constructor]
    cls.add_constructor([])
    ## random-variable-stream.h (module 'core'): double ns3::WeibullRandomVariable::GetScale() const [member function]
    cls.add_method('GetScale', 
                   'double', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::WeibullRandomVariable::GetShape() const [member function]
    cls.add_method('GetShape', 
                   'double', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::WeibullRandomVariable::GetBound() const [member function]
    cls.add_method('GetBound', 
                   'double', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::WeibullRandomVariable::GetValue(double scale, double shape, double bound) [member function]
    cls.add_method('GetValue', 
                   'double', 
                   [param('double', 'scale'), param('double', 'shape'), param('double', 'bound')])
    ## random-variable-stream.h (module 'core'): uint32_t ns3::WeibullRandomVariable::GetInteger(uint32_t scale, uint32_t shape, uint32_t bound) [member function]
    cls.add_method('GetInteger', 
                   'uint32_t', 
                   [param('uint32_t', 'scale'), param('uint32_t', 'shape'), param('uint32_t', 'bound')])
    ## random-variable-stream.h (module 'core'): double ns3::WeibullRandomVariable::GetValue() [member function]
    cls.add_method('GetValue', 
                   'double', 
                   [], 
                   is_virtual=True)
    ## random-variable-stream.h (module 'core'): uint32_t ns3::WeibullRandomVariable::GetInteger() [member function]
    cls.add_method('GetInteger', 
                   'uint32_t', 
                   [], 
                   is_virtual=True)
    return

def register_Ns3WifiMac_methods(root_module, cls):
    ## wifi-mac.h (module 'wifi'): ns3::WifiMac::WifiMac() [constructor]
    cls.add_constructor([])
    ## wifi-mac.h (module 'wifi'): ns3::WifiMac::WifiMac(ns3::WifiMac const & arg0) [constructor]
    cls.add_constructor([param('ns3::WifiMac const &', 'arg0')])
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::ConfigureStandard(ns3::WifiPhyStandard standard) [member function]
    cls.add_method('ConfigureStandard', 
                   'void', 
                   [param('ns3::WifiPhyStandard', 'standard')])
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::Enqueue(ns3::Ptr<const ns3::Packet> packet, ns3::Mac48Address to, ns3::Mac48Address from) [member function]
    cls.add_method('Enqueue', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet const >', 'packet'), param('ns3::Mac48Address', 'to'), param('ns3::Mac48Address', 'from')], 
                   is_pure_virtual=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::Enqueue(ns3::Ptr<const ns3::Packet> packet, ns3::Mac48Address to) [member function]
    cls.add_method('Enqueue', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet const >', 'packet'), param('ns3::Mac48Address', 'to')], 
                   is_pure_virtual=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): ns3::Time ns3::WifiMac::GetAckTimeout() const [member function]
    cls.add_method('GetAckTimeout', 
                   'ns3::Time', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): ns3::Mac48Address ns3::WifiMac::GetAddress() const [member function]
    cls.add_method('GetAddress', 
                   'ns3::Mac48Address', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): ns3::Time ns3::WifiMac::GetBasicBlockAckTimeout() const [member function]
    cls.add_method('GetBasicBlockAckTimeout', 
                   'ns3::Time', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): ns3::Mac48Address ns3::WifiMac::GetBssid() const [member function]
    cls.add_method('GetBssid', 
                   'ns3::Mac48Address', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): ns3::Time ns3::WifiMac::GetCompressedBlockAckTimeout() const [member function]
    cls.add_method('GetCompressedBlockAckTimeout', 
                   'ns3::Time', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): ns3::Time ns3::WifiMac::GetCtsTimeout() const [member function]
    cls.add_method('GetCtsTimeout', 
                   'ns3::Time', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): ns3::Time ns3::WifiMac::GetEifsNoDifs() const [member function]
    cls.add_method('GetEifsNoDifs', 
                   'ns3::Time', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): ns3::Time ns3::WifiMac::GetPifs() const [member function]
    cls.add_method('GetPifs', 
                   'ns3::Time', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): ns3::Time ns3::WifiMac::GetRifs() const [member function]
    cls.add_method('GetRifs', 
                   'ns3::Time', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): bool ns3::WifiMac::GetRifsSupported() const [member function]
    cls.add_method('GetRifsSupported', 
                   'bool', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): bool ns3::WifiMac::GetShortSlotTimeSupported() const [member function]
    cls.add_method('GetShortSlotTimeSupported', 
                   'bool', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): ns3::Time ns3::WifiMac::GetSifs() const [member function]
    cls.add_method('GetSifs', 
                   'ns3::Time', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): ns3::Time ns3::WifiMac::GetSlot() const [member function]
    cls.add_method('GetSlot', 
                   'ns3::Time', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): ns3::Ssid ns3::WifiMac::GetSsid() const [member function]
    cls.add_method('GetSsid', 
                   'ns3::Ssid', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): static ns3::TypeId ns3::WifiMac::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## wifi-mac.h (module 'wifi'): ns3::Ptr<ns3::WifiPhy> ns3::WifiMac::GetWifiPhy() const [member function]
    cls.add_method('GetWifiPhy', 
                   'ns3::Ptr< ns3::WifiPhy >', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): ns3::Ptr<ns3::WifiRemoteStationManager> ns3::WifiMac::GetWifiRemoteStationManager() const [member function]
    cls.add_method('GetWifiRemoteStationManager', 
                   'ns3::Ptr< ns3::WifiRemoteStationManager >', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::NotifyPromiscRx(ns3::Ptr<const ns3::Packet> packet) [member function]
    cls.add_method('NotifyPromiscRx', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet const >', 'packet')])
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::NotifyRx(ns3::Ptr<const ns3::Packet> packet) [member function]
    cls.add_method('NotifyRx', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet const >', 'packet')])
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::NotifyRxDrop(ns3::Ptr<const ns3::Packet> packet) [member function]
    cls.add_method('NotifyRxDrop', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet const >', 'packet')])
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::NotifyTx(ns3::Ptr<const ns3::Packet> packet) [member function]
    cls.add_method('NotifyTx', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet const >', 'packet')])
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::NotifyTxDrop(ns3::Ptr<const ns3::Packet> packet) [member function]
    cls.add_method('NotifyTxDrop', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet const >', 'packet')])
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::ResetWifiPhy() [member function]
    cls.add_method('ResetWifiPhy', 
                   'void', 
                   [], 
                   is_pure_virtual=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::SetAckTimeout(ns3::Time ackTimeout) [member function]
    cls.add_method('SetAckTimeout', 
                   'void', 
                   [param('ns3::Time', 'ackTimeout')], 
                   is_pure_virtual=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::SetAddress(ns3::Mac48Address address) [member function]
    cls.add_method('SetAddress', 
                   'void', 
                   [param('ns3::Mac48Address', 'address')], 
                   is_pure_virtual=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::SetBasicBlockAckTimeout(ns3::Time blockAckTimeout) [member function]
    cls.add_method('SetBasicBlockAckTimeout', 
                   'void', 
                   [param('ns3::Time', 'blockAckTimeout')], 
                   is_pure_virtual=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::SetCompressedBlockAckTimeout(ns3::Time blockAckTimeout) [member function]
    cls.add_method('SetCompressedBlockAckTimeout', 
                   'void', 
                   [param('ns3::Time', 'blockAckTimeout')], 
                   is_pure_virtual=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::SetCtsTimeout(ns3::Time ctsTimeout) [member function]
    cls.add_method('SetCtsTimeout', 
                   'void', 
                   [param('ns3::Time', 'ctsTimeout')], 
                   is_pure_virtual=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::SetEifsNoDifs(ns3::Time eifsNoDifs) [member function]
    cls.add_method('SetEifsNoDifs', 
                   'void', 
                   [param('ns3::Time', 'eifsNoDifs')], 
                   is_pure_virtual=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::SetForwardUpCallback(ns3::Callback<void, ns3::Ptr<ns3::Packet>, ns3::Mac48Address, ns3::Mac48Address, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> upCallback) [member function]
    cls.add_method('SetForwardUpCallback', 
                   'void', 
                   [param('ns3::Callback< void, ns3::Ptr< ns3::Packet >, ns3::Mac48Address, ns3::Mac48Address, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'upCallback')], 
                   is_pure_virtual=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::SetLinkDownCallback(ns3::Callback<void, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> linkDown) [member function]
    cls.add_method('SetLinkDownCallback', 
                   'void', 
                   [param('ns3::Callback< void, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'linkDown')], 
                   is_pure_virtual=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::SetLinkUpCallback(ns3::Callback<void, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> linkUp) [member function]
    cls.add_method('SetLinkUpCallback', 
                   'void', 
                   [param('ns3::Callback< void, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'linkUp')], 
                   is_pure_virtual=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::SetMaxPropagationDelay(ns3::Time delay) [member function]
    cls.add_method('SetMaxPropagationDelay', 
                   'void', 
                   [param('ns3::Time', 'delay')])
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::SetPifs(ns3::Time pifs) [member function]
    cls.add_method('SetPifs', 
                   'void', 
                   [param('ns3::Time', 'pifs')], 
                   is_pure_virtual=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::SetPromisc() [member function]
    cls.add_method('SetPromisc', 
                   'void', 
                   [], 
                   is_pure_virtual=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::SetRifs(ns3::Time rifs) [member function]
    cls.add_method('SetRifs', 
                   'void', 
                   [param('ns3::Time', 'rifs')], 
                   is_pure_virtual=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::SetShortSlotTimeSupported(bool enable) [member function]
    cls.add_method('SetShortSlotTimeSupported', 
                   'void', 
                   [param('bool', 'enable')], 
                   is_pure_virtual=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::SetSifs(ns3::Time sifs) [member function]
    cls.add_method('SetSifs', 
                   'void', 
                   [param('ns3::Time', 'sifs')], 
                   is_pure_virtual=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::SetSlot(ns3::Time slotTime) [member function]
    cls.add_method('SetSlot', 
                   'void', 
                   [param('ns3::Time', 'slotTime')], 
                   is_pure_virtual=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::SetSsid(ns3::Ssid ssid) [member function]
    cls.add_method('SetSsid', 
                   'void', 
                   [param('ns3::Ssid', 'ssid')], 
                   is_pure_virtual=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::SetWifiPhy(ns3::Ptr<ns3::WifiPhy> phy) [member function]
    cls.add_method('SetWifiPhy', 
                   'void', 
                   [param('ns3::Ptr< ns3::WifiPhy >', 'phy')], 
                   is_pure_virtual=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::SetWifiRemoteStationManager(ns3::Ptr<ns3::WifiRemoteStationManager> stationManager) [member function]
    cls.add_method('SetWifiRemoteStationManager', 
                   'void', 
                   [param('ns3::Ptr< ns3::WifiRemoteStationManager >', 'stationManager')], 
                   is_pure_virtual=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): bool ns3::WifiMac::SupportsSendFrom() const [member function]
    cls.add_method('SupportsSendFrom', 
                   'bool', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::ConfigureDcf(ns3::Ptr<ns3::Txop> dcf, uint32_t cwmin, uint32_t cwmax, bool isDsss, ns3::AcIndex ac) [member function]
    cls.add_method('ConfigureDcf', 
                   'void', 
                   [param('ns3::Ptr< ns3::Txop >', 'dcf'), param('uint32_t', 'cwmin'), param('uint32_t', 'cwmax'), param('bool', 'isDsss'), param('ns3::AcIndex', 'ac')], 
                   visibility='protected')
    ## wifi-mac.h (module 'wifi'): void ns3::WifiMac::FinishConfigureStandard(ns3::WifiPhyStandard standard) [member function]
    cls.add_method('FinishConfigureStandard', 
                   'void', 
                   [param('ns3::WifiPhyStandard', 'standard')], 
                   is_pure_virtual=True, visibility='private', is_virtual=True)
    return

def register_Ns3WifiRemoteStationManager_methods(root_module, cls):
    ## wifi-remote-station-manager.h (module 'wifi'): static ns3::TypeId ns3::WifiRemoteStationManager::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationManager::WifiRemoteStationManager() [constructor]
    cls.add_constructor([])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::SetupPhy(ns3::Ptr<ns3::WifiPhy> const phy) [member function]
    cls.add_method('SetupPhy', 
                   'void', 
                   [param('ns3::Ptr< ns3::WifiPhy > const', 'phy')], 
                   is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::SetupMac(ns3::Ptr<ns3::WifiMac> const mac) [member function]
    cls.add_method('SetupMac', 
                   'void', 
                   [param('ns3::Ptr< ns3::WifiMac > const', 'mac')], 
                   is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::SetMaxSsrc(uint32_t maxSsrc) [member function]
    cls.add_method('SetMaxSsrc', 
                   'void', 
                   [param('uint32_t', 'maxSsrc')])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::SetMaxSlrc(uint32_t maxSlrc) [member function]
    cls.add_method('SetMaxSlrc', 
                   'void', 
                   [param('uint32_t', 'maxSlrc')])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::SetRtsCtsThreshold(uint32_t threshold) [member function]
    cls.add_method('SetRtsCtsThreshold', 
                   'void', 
                   [param('uint32_t', 'threshold')])
    ## wifi-remote-station-manager.h (module 'wifi'): uint32_t ns3::WifiRemoteStationManager::GetFragmentationThreshold() const [member function]
    cls.add_method('GetFragmentationThreshold', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::SetFragmentationThreshold(uint32_t threshold) [member function]
    cls.add_method('SetFragmentationThreshold', 
                   'void', 
                   [param('uint32_t', 'threshold')])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::UpdateFragmentationThreshold() [member function]
    cls.add_method('UpdateFragmentationThreshold', 
                   'void', 
                   [])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::SetQosSupport(ns3::Mac48Address from, bool qosSupported) [member function]
    cls.add_method('SetQosSupport', 
                   'void', 
                   [param('ns3::Mac48Address', 'from'), param('bool', 'qosSupported')])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::AddStationHtCapabilities(ns3::Mac48Address from, ns3::HtCapabilities htcapabilities) [member function]
    cls.add_method('AddStationHtCapabilities', 
                   'void', 
                   [param('ns3::Mac48Address', 'from'), param('ns3::HtCapabilities', 'htcapabilities')])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::AddStationVhtCapabilities(ns3::Mac48Address from, ns3::VhtCapabilities vhtcapabilities) [member function]
    cls.add_method('AddStationVhtCapabilities', 
                   'void', 
                   [param('ns3::Mac48Address', 'from'), param('ns3::VhtCapabilities', 'vhtcapabilities')])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::AddStationHeCapabilities(ns3::Mac48Address from, ns3::HeCapabilities hecapabilities) [member function]
    cls.add_method('AddStationHeCapabilities', 
                   'void', 
                   [param('ns3::Mac48Address', 'from'), param('ns3::HeCapabilities', 'hecapabilities')])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::SetHtSupported(bool enable) [member function]
    cls.add_method('SetHtSupported', 
                   'void', 
                   [param('bool', 'enable')], 
                   is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::HasHtSupported() const [member function]
    cls.add_method('HasHtSupported', 
                   'bool', 
                   [], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::SetVhtSupported(bool enable) [member function]
    cls.add_method('SetVhtSupported', 
                   'void', 
                   [param('bool', 'enable')], 
                   is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::HasVhtSupported() const [member function]
    cls.add_method('HasVhtSupported', 
                   'bool', 
                   [], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::SetHeSupported(bool enable) [member function]
    cls.add_method('SetHeSupported', 
                   'void', 
                   [param('bool', 'enable')], 
                   is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::HasHeSupported() const [member function]
    cls.add_method('HasHeSupported', 
                   'bool', 
                   [], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::SetPcfSupported(bool enable) [member function]
    cls.add_method('SetPcfSupported', 
                   'void', 
                   [param('bool', 'enable')], 
                   is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::HasPcfSupported() const [member function]
    cls.add_method('HasPcfSupported', 
                   'bool', 
                   [], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::SetUseNonErpProtection(bool enable) [member function]
    cls.add_method('SetUseNonErpProtection', 
                   'void', 
                   [param('bool', 'enable')])
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::GetUseNonErpProtection() const [member function]
    cls.add_method('GetUseNonErpProtection', 
                   'bool', 
                   [], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::SetUseNonHtProtection(bool enable) [member function]
    cls.add_method('SetUseNonHtProtection', 
                   'void', 
                   [param('bool', 'enable')])
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::GetUseNonHtProtection() const [member function]
    cls.add_method('GetUseNonHtProtection', 
                   'bool', 
                   [], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::SetUseGreenfieldProtection(bool enable) [member function]
    cls.add_method('SetUseGreenfieldProtection', 
                   'void', 
                   [param('bool', 'enable')])
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::GetUseGreenfieldProtection() const [member function]
    cls.add_method('GetUseGreenfieldProtection', 
                   'bool', 
                   [], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::SetShortPreambleEnabled(bool enable) [member function]
    cls.add_method('SetShortPreambleEnabled', 
                   'void', 
                   [param('bool', 'enable')])
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::GetShortPreambleEnabled() const [member function]
    cls.add_method('GetShortPreambleEnabled', 
                   'bool', 
                   [], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::SetShortSlotTimeEnabled(bool enable) [member function]
    cls.add_method('SetShortSlotTimeEnabled', 
                   'void', 
                   [param('bool', 'enable')])
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::GetShortSlotTimeEnabled() const [member function]
    cls.add_method('GetShortSlotTimeEnabled', 
                   'bool', 
                   [], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::SetRifsPermitted(bool allow) [member function]
    cls.add_method('SetRifsPermitted', 
                   'void', 
                   [param('bool', 'allow')])
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::GetRifsPermitted() const [member function]
    cls.add_method('GetRifsPermitted', 
                   'bool', 
                   [], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::Reset() [member function]
    cls.add_method('Reset', 
                   'void', 
                   [])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::AddBasicMode(ns3::WifiMode mode) [member function]
    cls.add_method('AddBasicMode', 
                   'void', 
                   [param('ns3::WifiMode', 'mode')])
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiMode ns3::WifiRemoteStationManager::GetDefaultMode() const [member function]
    cls.add_method('GetDefaultMode', 
                   'ns3::WifiMode', 
                   [], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): uint8_t ns3::WifiRemoteStationManager::GetNBasicModes() const [member function]
    cls.add_method('GetNBasicModes', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiMode ns3::WifiRemoteStationManager::GetBasicMode(uint8_t i) const [member function]
    cls.add_method('GetBasicMode', 
                   'ns3::WifiMode', 
                   [param('uint8_t', 'i')], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): uint32_t ns3::WifiRemoteStationManager::GetNNonErpBasicModes() const [member function]
    cls.add_method('GetNNonErpBasicModes', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiMode ns3::WifiRemoteStationManager::GetNonErpBasicMode(uint8_t i) const [member function]
    cls.add_method('GetNonErpBasicMode', 
                   'ns3::WifiMode', 
                   [param('uint8_t', 'i')], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::GetGreenfieldSupported(ns3::Mac48Address address) const [member function]
    cls.add_method('GetGreenfieldSupported', 
                   'bool', 
                   [param('ns3::Mac48Address', 'address')], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::GetShortPreambleSupported(ns3::Mac48Address address) const [member function]
    cls.add_method('GetShortPreambleSupported', 
                   'bool', 
                   [param('ns3::Mac48Address', 'address')], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::GetShortSlotTimeSupported(ns3::Mac48Address address) const [member function]
    cls.add_method('GetShortSlotTimeSupported', 
                   'bool', 
                   [param('ns3::Mac48Address', 'address')], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::GetQosSupported(ns3::Mac48Address address) const [member function]
    cls.add_method('GetQosSupported', 
                   'bool', 
                   [param('ns3::Mac48Address', 'address')], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::AddBasicMcs(ns3::WifiMode mcs) [member function]
    cls.add_method('AddBasicMcs', 
                   'void', 
                   [param('ns3::WifiMode', 'mcs')])
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiMode ns3::WifiRemoteStationManager::GetDefaultMcs() const [member function]
    cls.add_method('GetDefaultMcs', 
                   'ns3::WifiMode', 
                   [], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): uint8_t ns3::WifiRemoteStationManager::GetNBasicMcs() const [member function]
    cls.add_method('GetNBasicMcs', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiMode ns3::WifiRemoteStationManager::GetBasicMcs(uint8_t i) const [member function]
    cls.add_method('GetBasicMcs', 
                   'ns3::WifiMode', 
                   [param('uint8_t', 'i')], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::AddSupportedMcs(ns3::Mac48Address address, ns3::WifiMode mcs) [member function]
    cls.add_method('AddSupportedMcs', 
                   'void', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMode', 'mcs')])
    ## wifi-remote-station-manager.h (module 'wifi'): uint16_t ns3::WifiRemoteStationManager::GetChannelWidthSupported(ns3::Mac48Address address) const [member function]
    cls.add_method('GetChannelWidthSupported', 
                   'uint16_t', 
                   [param('ns3::Mac48Address', 'address')], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::GetShortGuardInterval(ns3::Mac48Address address) const [member function]
    cls.add_method('GetShortGuardInterval', 
                   'bool', 
                   [param('ns3::Mac48Address', 'address')], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): uint8_t ns3::WifiRemoteStationManager::GetNumberOfSupportedStreams(ns3::Mac48Address address) const [member function]
    cls.add_method('GetNumberOfSupportedStreams', 
                   'uint8_t', 
                   [param('ns3::Mac48Address', 'address')], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): uint8_t ns3::WifiRemoteStationManager::GetNMcsSupported(ns3::Mac48Address address) const [member function]
    cls.add_method('GetNMcsSupported', 
                   'uint8_t', 
                   [param('ns3::Mac48Address', 'address')], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::GetHtSupported(ns3::Mac48Address address) const [member function]
    cls.add_method('GetHtSupported', 
                   'bool', 
                   [param('ns3::Mac48Address', 'address')], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::GetVhtSupported(ns3::Mac48Address address) const [member function]
    cls.add_method('GetVhtSupported', 
                   'bool', 
                   [param('ns3::Mac48Address', 'address')], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiMode ns3::WifiRemoteStationManager::GetNonUnicastMode() const [member function]
    cls.add_method('GetNonUnicastMode', 
                   'ns3::WifiMode', 
                   [], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::AddSupportedMode(ns3::Mac48Address address, ns3::WifiMode mode) [member function]
    cls.add_method('AddSupportedMode', 
                   'void', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMode', 'mode')])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::AddAllSupportedModes(ns3::Mac48Address address) [member function]
    cls.add_method('AddAllSupportedModes', 
                   'void', 
                   [param('ns3::Mac48Address', 'address')])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::AddAllSupportedMcs(ns3::Mac48Address address) [member function]
    cls.add_method('AddAllSupportedMcs', 
                   'void', 
                   [param('ns3::Mac48Address', 'address')])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::RemoveAllSupportedMcs(ns3::Mac48Address address) [member function]
    cls.add_method('RemoveAllSupportedMcs', 
                   'void', 
                   [param('ns3::Mac48Address', 'address')])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::AddSupportedPlcpPreamble(ns3::Mac48Address address, bool isShortPreambleSupported) [member function]
    cls.add_method('AddSupportedPlcpPreamble', 
                   'void', 
                   [param('ns3::Mac48Address', 'address'), param('bool', 'isShortPreambleSupported')])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::AddSupportedErpSlotTime(ns3::Mac48Address address, bool isShortSlotTimeSupported) [member function]
    cls.add_method('AddSupportedErpSlotTime', 
                   'void', 
                   [param('ns3::Mac48Address', 'address'), param('bool', 'isShortSlotTimeSupported')])
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::IsBrandNew(ns3::Mac48Address address) const [member function]
    cls.add_method('IsBrandNew', 
                   'bool', 
                   [param('ns3::Mac48Address', 'address')], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::IsAssociated(ns3::Mac48Address address) const [member function]
    cls.add_method('IsAssociated', 
                   'bool', 
                   [param('ns3::Mac48Address', 'address')], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::IsWaitAssocTxOk(ns3::Mac48Address address) const [member function]
    cls.add_method('IsWaitAssocTxOk', 
                   'bool', 
                   [param('ns3::Mac48Address', 'address')], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::RecordWaitAssocTxOk(ns3::Mac48Address address) [member function]
    cls.add_method('RecordWaitAssocTxOk', 
                   'void', 
                   [param('ns3::Mac48Address', 'address')])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::RecordGotAssocTxOk(ns3::Mac48Address address) [member function]
    cls.add_method('RecordGotAssocTxOk', 
                   'void', 
                   [param('ns3::Mac48Address', 'address')])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::RecordGotAssocTxFailed(ns3::Mac48Address address) [member function]
    cls.add_method('RecordGotAssocTxFailed', 
                   'void', 
                   [param('ns3::Mac48Address', 'address')])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::RecordDisassociated(ns3::Mac48Address address) [member function]
    cls.add_method('RecordDisassociated', 
                   'void', 
                   [param('ns3::Mac48Address', 'address')])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::PrepareForQueue(ns3::Mac48Address address, ns3::WifiMacHeader const * header, ns3::Ptr<const ns3::Packet> packet) [member function]
    cls.add_method('PrepareForQueue', 
                   'void', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMacHeader const *', 'header'), param('ns3::Ptr< ns3::Packet const >', 'packet')])
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiTxVector ns3::WifiRemoteStationManager::GetDataTxVector(ns3::Mac48Address address, ns3::WifiMacHeader const * header, ns3::Ptr<const ns3::Packet> packet) [member function]
    cls.add_method('GetDataTxVector', 
                   'ns3::WifiTxVector', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMacHeader const *', 'header'), param('ns3::Ptr< ns3::Packet const >', 'packet')])
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiTxVector ns3::WifiRemoteStationManager::GetRtsTxVector(ns3::Mac48Address address, ns3::WifiMacHeader const * header, ns3::Ptr<const ns3::Packet> packet) [member function]
    cls.add_method('GetRtsTxVector', 
                   'ns3::WifiTxVector', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMacHeader const *', 'header'), param('ns3::Ptr< ns3::Packet const >', 'packet')])
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiTxVector ns3::WifiRemoteStationManager::GetCtsToSelfTxVector(ns3::WifiMacHeader const * header, ns3::Ptr<const ns3::Packet> packet) [member function]
    cls.add_method('GetCtsToSelfTxVector', 
                   'ns3::WifiTxVector', 
                   [param('ns3::WifiMacHeader const *', 'header'), param('ns3::Ptr< ns3::Packet const >', 'packet')])
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiTxVector ns3::WifiRemoteStationManager::DoGetCtsToSelfTxVector() [member function]
    cls.add_method('DoGetCtsToSelfTxVector', 
                   'ns3::WifiTxVector', 
                   [])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::ReportRtsFailed(ns3::Mac48Address address, ns3::WifiMacHeader const * header) [member function]
    cls.add_method('ReportRtsFailed', 
                   'void', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMacHeader const *', 'header')])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::ReportDataFailed(ns3::Mac48Address address, ns3::WifiMacHeader const * header, uint32_t packetSize) [member function]
    cls.add_method('ReportDataFailed', 
                   'void', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMacHeader const *', 'header'), param('uint32_t', 'packetSize')])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::ReportRtsOk(ns3::Mac48Address address, ns3::WifiMacHeader const * header, double ctsSnr, ns3::WifiMode ctsMode, double rtsSnr) [member function]
    cls.add_method('ReportRtsOk', 
                   'void', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMacHeader const *', 'header'), param('double', 'ctsSnr'), param('ns3::WifiMode', 'ctsMode'), param('double', 'rtsSnr')])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::ReportDataOk(ns3::Mac48Address address, ns3::WifiMacHeader const * header, double ackSnr, ns3::WifiMode ackMode, double dataSnr, uint32_t packetSize) [member function]
    cls.add_method('ReportDataOk', 
                   'void', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMacHeader const *', 'header'), param('double', 'ackSnr'), param('ns3::WifiMode', 'ackMode'), param('double', 'dataSnr'), param('uint32_t', 'packetSize')])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::ReportFinalRtsFailed(ns3::Mac48Address address, ns3::WifiMacHeader const * header) [member function]
    cls.add_method('ReportFinalRtsFailed', 
                   'void', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMacHeader const *', 'header')])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::ReportFinalDataFailed(ns3::Mac48Address address, ns3::WifiMacHeader const * header, uint32_t packetSize) [member function]
    cls.add_method('ReportFinalDataFailed', 
                   'void', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMacHeader const *', 'header'), param('uint32_t', 'packetSize')])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::ReportAmpduTxStatus(ns3::Mac48Address address, uint8_t tid, uint8_t nSuccessfulMpdus, uint8_t nFailedMpdus, double rxSnr, double dataSnr) [member function]
    cls.add_method('ReportAmpduTxStatus', 
                   'void', 
                   [param('ns3::Mac48Address', 'address'), param('uint8_t', 'tid'), param('uint8_t', 'nSuccessfulMpdus'), param('uint8_t', 'nFailedMpdus'), param('double', 'rxSnr'), param('double', 'dataSnr')])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::ReportRxOk(ns3::Mac48Address address, ns3::WifiMacHeader const * header, double rxSnr, ns3::WifiMode txMode) [member function]
    cls.add_method('ReportRxOk', 
                   'void', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMacHeader const *', 'header'), param('double', 'rxSnr'), param('ns3::WifiMode', 'txMode')])
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::NeedRts(ns3::Mac48Address address, ns3::WifiMacHeader const * header, ns3::Ptr<const ns3::Packet> packet, ns3::WifiTxVector txVector) [member function]
    cls.add_method('NeedRts', 
                   'bool', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMacHeader const *', 'header'), param('ns3::Ptr< ns3::Packet const >', 'packet'), param('ns3::WifiTxVector', 'txVector')])
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::NeedCtsToSelf(ns3::WifiTxVector txVector) [member function]
    cls.add_method('NeedCtsToSelf', 
                   'bool', 
                   [param('ns3::WifiTxVector', 'txVector')])
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::NeedRetransmission(ns3::Mac48Address address, ns3::WifiMacHeader const * header, ns3::Ptr<const ns3::Packet> packet) [member function]
    cls.add_method('NeedRetransmission', 
                   'bool', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMacHeader const *', 'header'), param('ns3::Ptr< ns3::Packet const >', 'packet')])
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::NeedFragmentation(ns3::Mac48Address address, ns3::WifiMacHeader const * header, ns3::Ptr<const ns3::Packet> packet) [member function]
    cls.add_method('NeedFragmentation', 
                   'bool', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMacHeader const *', 'header'), param('ns3::Ptr< ns3::Packet const >', 'packet')])
    ## wifi-remote-station-manager.h (module 'wifi'): uint32_t ns3::WifiRemoteStationManager::GetFragmentSize(ns3::Mac48Address address, ns3::WifiMacHeader const * header, ns3::Ptr<const ns3::Packet> packet, uint32_t fragmentNumber) [member function]
    cls.add_method('GetFragmentSize', 
                   'uint32_t', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMacHeader const *', 'header'), param('ns3::Ptr< ns3::Packet const >', 'packet'), param('uint32_t', 'fragmentNumber')])
    ## wifi-remote-station-manager.h (module 'wifi'): uint32_t ns3::WifiRemoteStationManager::GetFragmentOffset(ns3::Mac48Address address, ns3::WifiMacHeader const * header, ns3::Ptr<const ns3::Packet> packet, uint32_t fragmentNumber) [member function]
    cls.add_method('GetFragmentOffset', 
                   'uint32_t', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMacHeader const *', 'header'), param('ns3::Ptr< ns3::Packet const >', 'packet'), param('uint32_t', 'fragmentNumber')])
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::IsLastFragment(ns3::Mac48Address address, ns3::WifiMacHeader const * header, ns3::Ptr<const ns3::Packet> packet, uint32_t fragmentNumber) [member function]
    cls.add_method('IsLastFragment', 
                   'bool', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMacHeader const *', 'header'), param('ns3::Ptr< ns3::Packet const >', 'packet'), param('uint32_t', 'fragmentNumber')])
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiTxVector ns3::WifiRemoteStationManager::GetCtsTxVector(ns3::Mac48Address address, ns3::WifiMode rtsMode) [member function]
    cls.add_method('GetCtsTxVector', 
                   'ns3::WifiTxVector', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMode', 'rtsMode')])
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiTxVector ns3::WifiRemoteStationManager::GetAckTxVector(ns3::Mac48Address address, ns3::WifiMode dataMode) [member function]
    cls.add_method('GetAckTxVector', 
                   'ns3::WifiTxVector', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMode', 'dataMode')])
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiTxVector ns3::WifiRemoteStationManager::GetBlockAckTxVector(ns3::Mac48Address address, ns3::WifiMode dataMode) [member function]
    cls.add_method('GetBlockAckTxVector', 
                   'ns3::WifiTxVector', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMode', 'dataMode')])
    ## wifi-remote-station-manager.h (module 'wifi'): uint8_t ns3::WifiRemoteStationManager::GetDefaultTxPowerLevel() const [member function]
    cls.add_method('GetDefaultTxPowerLevel', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationInfo ns3::WifiRemoteStationManager::GetInfo(ns3::Mac48Address address) [member function]
    cls.add_method('GetInfo', 
                   'ns3::WifiRemoteStationInfo', 
                   [param('ns3::Mac48Address', 'address')])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::SetDefaultTxPowerLevel(uint8_t txPower) [member function]
    cls.add_method('SetDefaultTxPowerLevel', 
                   'void', 
                   [param('uint8_t', 'txPower')])
    ## wifi-remote-station-manager.h (module 'wifi'): uint8_t ns3::WifiRemoteStationManager::GetNumberOfAntennas() [member function]
    cls.add_method('GetNumberOfAntennas', 
                   'uint8_t', 
                   [])
    ## wifi-remote-station-manager.h (module 'wifi'): uint8_t ns3::WifiRemoteStationManager::GetMaxNumberOfTransmitStreams() [member function]
    cls.add_method('GetMaxNumberOfTransmitStreams', 
                   'uint8_t', 
                   [])
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStationManager::WifiRemoteStationManager(ns3::WifiRemoteStationManager const & arg0) [constructor]
    cls.add_constructor([param('ns3::WifiRemoteStationManager const &', 'arg0')])
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::DoDispose() [member function]
    cls.add_method('DoDispose', 
                   'void', 
                   [], 
                   visibility='protected', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiMode ns3::WifiRemoteStationManager::GetSupported(ns3::WifiRemoteStation const * station, uint8_t i) const [member function]
    cls.add_method('GetSupported', 
                   'ns3::WifiMode', 
                   [param('ns3::WifiRemoteStation const *', 'station'), param('uint8_t', 'i')], 
                   is_const=True, visibility='protected')
    ## wifi-remote-station-manager.h (module 'wifi'): uint8_t ns3::WifiRemoteStationManager::GetNSupported(ns3::WifiRemoteStation const * station) const [member function]
    cls.add_method('GetNSupported', 
                   'uint8_t', 
                   [param('ns3::WifiRemoteStation const *', 'station')], 
                   is_const=True, visibility='protected')
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::GetQosSupported(ns3::WifiRemoteStation const * station) const [member function]
    cls.add_method('GetQosSupported', 
                   'bool', 
                   [param('ns3::WifiRemoteStation const *', 'station')], 
                   is_const=True, visibility='protected')
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::GetHtSupported(ns3::WifiRemoteStation const * station) const [member function]
    cls.add_method('GetHtSupported', 
                   'bool', 
                   [param('ns3::WifiRemoteStation const *', 'station')], 
                   is_const=True, visibility='protected')
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::GetVhtSupported(ns3::WifiRemoteStation const * station) const [member function]
    cls.add_method('GetVhtSupported', 
                   'bool', 
                   [param('ns3::WifiRemoteStation const *', 'station')], 
                   is_const=True, visibility='protected')
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::GetHeSupported(ns3::WifiRemoteStation const * station) const [member function]
    cls.add_method('GetHeSupported', 
                   'bool', 
                   [param('ns3::WifiRemoteStation const *', 'station')], 
                   is_const=True, visibility='protected')
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiMode ns3::WifiRemoteStationManager::GetMcsSupported(ns3::WifiRemoteStation const * station, uint8_t i) const [member function]
    cls.add_method('GetMcsSupported', 
                   'ns3::WifiMode', 
                   [param('ns3::WifiRemoteStation const *', 'station'), param('uint8_t', 'i')], 
                   is_const=True, visibility='protected')
    ## wifi-remote-station-manager.h (module 'wifi'): uint8_t ns3::WifiRemoteStationManager::GetNMcsSupported(ns3::WifiRemoteStation const * station) const [member function]
    cls.add_method('GetNMcsSupported', 
                   'uint8_t', 
                   [param('ns3::WifiRemoteStation const *', 'station')], 
                   is_const=True, visibility='protected')
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiMode ns3::WifiRemoteStationManager::GetNonErpSupported(ns3::WifiRemoteStation const * station, uint8_t i) const [member function]
    cls.add_method('GetNonErpSupported', 
                   'ns3::WifiMode', 
                   [param('ns3::WifiRemoteStation const *', 'station'), param('uint8_t', 'i')], 
                   is_const=True, visibility='protected')
    ## wifi-remote-station-manager.h (module 'wifi'): uint32_t ns3::WifiRemoteStationManager::GetNNonErpSupported(ns3::WifiRemoteStation const * station) const [member function]
    cls.add_method('GetNNonErpSupported', 
                   'uint32_t', 
                   [param('ns3::WifiRemoteStation const *', 'station')], 
                   is_const=True, visibility='protected')
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::Mac48Address ns3::WifiRemoteStationManager::GetAddress(ns3::WifiRemoteStation const * station) const [member function]
    cls.add_method('GetAddress', 
                   'ns3::Mac48Address', 
                   [param('ns3::WifiRemoteStation const *', 'station')], 
                   is_const=True, visibility='protected')
    ## wifi-remote-station-manager.h (module 'wifi'): uint16_t ns3::WifiRemoteStationManager::GetChannelWidth(ns3::WifiRemoteStation const * station) const [member function]
    cls.add_method('GetChannelWidth', 
                   'uint16_t', 
                   [param('ns3::WifiRemoteStation const *', 'station')], 
                   is_const=True, visibility='protected')
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::GetShortGuardInterval(ns3::WifiRemoteStation const * station) const [member function]
    cls.add_method('GetShortGuardInterval', 
                   'bool', 
                   [param('ns3::WifiRemoteStation const *', 'station')], 
                   is_const=True, visibility='protected')
    ## wifi-remote-station-manager.h (module 'wifi'): uint16_t ns3::WifiRemoteStationManager::GetGuardInterval(ns3::WifiRemoteStation const * station) const [member function]
    cls.add_method('GetGuardInterval', 
                   'uint16_t', 
                   [param('ns3::WifiRemoteStation const *', 'station')], 
                   is_const=True, visibility='protected')
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::GetAggregation(ns3::WifiRemoteStation const * station) const [member function]
    cls.add_method('GetAggregation', 
                   'bool', 
                   [param('ns3::WifiRemoteStation const *', 'station')], 
                   is_const=True, visibility='protected')
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::GetGreenfield(ns3::WifiRemoteStation const * station) const [member function]
    cls.add_method('GetGreenfield', 
                   'bool', 
                   [param('ns3::WifiRemoteStation const *', 'station')], 
                   is_const=True, visibility='protected')
    ## wifi-remote-station-manager.h (module 'wifi'): uint8_t ns3::WifiRemoteStationManager::GetNumberOfSupportedStreams(ns3::WifiRemoteStation const * station) const [member function]
    cls.add_method('GetNumberOfSupportedStreams', 
                   'uint8_t', 
                   [param('ns3::WifiRemoteStation const *', 'station')], 
                   is_const=True, visibility='protected')
    ## wifi-remote-station-manager.h (module 'wifi'): uint8_t ns3::WifiRemoteStationManager::GetNess(ns3::WifiRemoteStation const * station) const [member function]
    cls.add_method('GetNess', 
                   'uint8_t', 
                   [param('ns3::WifiRemoteStation const *', 'station')], 
                   is_const=True, visibility='protected')
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiPreamble ns3::WifiRemoteStationManager::GetPreambleForTransmission(ns3::WifiMode mode, ns3::Mac48Address dest) [member function]
    cls.add_method('GetPreambleForTransmission', 
                   'ns3::WifiPreamble', 
                   [param('ns3::WifiMode', 'mode'), param('ns3::Mac48Address', 'dest')], 
                   visibility='protected')
    ## wifi-remote-station-manager.h (module 'wifi'): static uint16_t ns3::WifiRemoteStationManager::GetChannelWidthForTransmission(ns3::WifiMode mode, uint16_t maxSupportedChannelWidth) [member function]
    cls.add_method('GetChannelWidthForTransmission', 
                   'uint16_t', 
                   [param('ns3::WifiMode', 'mode'), param('uint16_t', 'maxSupportedChannelWidth')], 
                   is_static=True, visibility='protected')
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::Ptr<ns3::WifiPhy> ns3::WifiRemoteStationManager::GetPhy() const [member function]
    cls.add_method('GetPhy', 
                   'ns3::Ptr< ns3::WifiPhy >', 
                   [], 
                   is_const=True, visibility='protected')
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::Ptr<ns3::WifiMac> ns3::WifiRemoteStationManager::GetMac() const [member function]
    cls.add_method('GetMac', 
                   'ns3::Ptr< ns3::WifiMac >', 
                   [], 
                   is_const=True, visibility='protected')
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::DoNeedRts(ns3::WifiRemoteStation * station, ns3::Ptr<const ns3::Packet> packet, bool normally) [member function]
    cls.add_method('DoNeedRts', 
                   'bool', 
                   [param('ns3::WifiRemoteStation *', 'station'), param('ns3::Ptr< ns3::Packet const >', 'packet'), param('bool', 'normally')], 
                   visibility='private', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::DoNeedRetransmission(ns3::WifiRemoteStation * station, ns3::Ptr<const ns3::Packet> packet, bool normally) [member function]
    cls.add_method('DoNeedRetransmission', 
                   'bool', 
                   [param('ns3::WifiRemoteStation *', 'station'), param('ns3::Ptr< ns3::Packet const >', 'packet'), param('bool', 'normally')], 
                   visibility='private', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::DoNeedFragmentation(ns3::WifiRemoteStation * station, ns3::Ptr<const ns3::Packet> packet, bool normally) [member function]
    cls.add_method('DoNeedFragmentation', 
                   'bool', 
                   [param('ns3::WifiRemoteStation *', 'station'), param('ns3::Ptr< ns3::Packet const >', 'packet'), param('bool', 'normally')], 
                   visibility='private', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): bool ns3::WifiRemoteStationManager::IsLowLatency() const [member function]
    cls.add_method('IsLowLatency', 
                   'bool', 
                   [], 
                   is_pure_virtual=True, is_const=True, visibility='private', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiRemoteStation * ns3::WifiRemoteStationManager::DoCreateStation() const [member function]
    cls.add_method('DoCreateStation', 
                   'ns3::WifiRemoteStation *', 
                   [], 
                   is_pure_virtual=True, is_const=True, visibility='private', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiTxVector ns3::WifiRemoteStationManager::DoGetDataTxVector(ns3::WifiRemoteStation * station) [member function]
    cls.add_method('DoGetDataTxVector', 
                   'ns3::WifiTxVector', 
                   [param('ns3::WifiRemoteStation *', 'station')], 
                   is_pure_virtual=True, visibility='private', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): ns3::WifiTxVector ns3::WifiRemoteStationManager::DoGetRtsTxVector(ns3::WifiRemoteStation * station) [member function]
    cls.add_method('DoGetRtsTxVector', 
                   'ns3::WifiTxVector', 
                   [param('ns3::WifiRemoteStation *', 'station')], 
                   is_pure_virtual=True, visibility='private', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): uint8_t ns3::WifiRemoteStationManager::DoGetCtsTxPowerLevel(ns3::Mac48Address address, ns3::WifiMode ctsMode) [member function]
    cls.add_method('DoGetCtsTxPowerLevel', 
                   'uint8_t', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMode', 'ctsMode')], 
                   visibility='private', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): uint8_t ns3::WifiRemoteStationManager::DoGetAckTxPowerLevel(ns3::Mac48Address address, ns3::WifiMode ackMode) [member function]
    cls.add_method('DoGetAckTxPowerLevel', 
                   'uint8_t', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMode', 'ackMode')], 
                   visibility='private', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): uint8_t ns3::WifiRemoteStationManager::DoGetBlockAckTxPowerLevel(ns3::Mac48Address address, ns3::WifiMode blockAckMode) [member function]
    cls.add_method('DoGetBlockAckTxPowerLevel', 
                   'uint8_t', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMode', 'blockAckMode')], 
                   visibility='private', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): uint16_t ns3::WifiRemoteStationManager::DoGetCtsTxChannelWidth(ns3::Mac48Address address, ns3::WifiMode ctsMode) [member function]
    cls.add_method('DoGetCtsTxChannelWidth', 
                   'uint16_t', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMode', 'ctsMode')], 
                   visibility='private', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): uint16_t ns3::WifiRemoteStationManager::DoGetCtsTxGuardInterval(ns3::Mac48Address address, ns3::WifiMode ctsMode) [member function]
    cls.add_method('DoGetCtsTxGuardInterval', 
                   'uint16_t', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMode', 'ctsMode')], 
                   visibility='private', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): uint8_t ns3::WifiRemoteStationManager::DoGetCtsTxNss(ns3::Mac48Address address, ns3::WifiMode ctsMode) [member function]
    cls.add_method('DoGetCtsTxNss', 
                   'uint8_t', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMode', 'ctsMode')], 
                   visibility='private', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): uint8_t ns3::WifiRemoteStationManager::DoGetCtsTxNess(ns3::Mac48Address address, ns3::WifiMode ctsMode) [member function]
    cls.add_method('DoGetCtsTxNess', 
                   'uint8_t', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMode', 'ctsMode')], 
                   visibility='private', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): uint16_t ns3::WifiRemoteStationManager::DoGetAckTxChannelWidth(ns3::Mac48Address address, ns3::WifiMode ctsMode) [member function]
    cls.add_method('DoGetAckTxChannelWidth', 
                   'uint16_t', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMode', 'ctsMode')], 
                   visibility='private', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): uint16_t ns3::WifiRemoteStationManager::DoGetAckTxGuardInterval(ns3::Mac48Address address, ns3::WifiMode ackMode) [member function]
    cls.add_method('DoGetAckTxGuardInterval', 
                   'uint16_t', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMode', 'ackMode')], 
                   visibility='private', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): uint8_t ns3::WifiRemoteStationManager::DoGetAckTxNss(ns3::Mac48Address address, ns3::WifiMode ackMode) [member function]
    cls.add_method('DoGetAckTxNss', 
                   'uint8_t', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMode', 'ackMode')], 
                   visibility='private', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): uint8_t ns3::WifiRemoteStationManager::DoGetAckTxNess(ns3::Mac48Address address, ns3::WifiMode ackMode) [member function]
    cls.add_method('DoGetAckTxNess', 
                   'uint8_t', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMode', 'ackMode')], 
                   visibility='private', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): uint16_t ns3::WifiRemoteStationManager::DoGetBlockAckTxChannelWidth(ns3::Mac48Address address, ns3::WifiMode ctsMode) [member function]
    cls.add_method('DoGetBlockAckTxChannelWidth', 
                   'uint16_t', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMode', 'ctsMode')], 
                   visibility='private', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): uint16_t ns3::WifiRemoteStationManager::DoGetBlockAckTxGuardInterval(ns3::Mac48Address address, ns3::WifiMode blockAckMode) [member function]
    cls.add_method('DoGetBlockAckTxGuardInterval', 
                   'uint16_t', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMode', 'blockAckMode')], 
                   visibility='private', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): uint8_t ns3::WifiRemoteStationManager::DoGetBlockAckTxNss(ns3::Mac48Address address, ns3::WifiMode blockAckMode) [member function]
    cls.add_method('DoGetBlockAckTxNss', 
                   'uint8_t', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMode', 'blockAckMode')], 
                   visibility='private', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): uint8_t ns3::WifiRemoteStationManager::DoGetBlockAckTxNess(ns3::Mac48Address address, ns3::WifiMode blockAckMode) [member function]
    cls.add_method('DoGetBlockAckTxNess', 
                   'uint8_t', 
                   [param('ns3::Mac48Address', 'address'), param('ns3::WifiMode', 'blockAckMode')], 
                   visibility='private', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::DoReportRtsFailed(ns3::WifiRemoteStation * station) [member function]
    cls.add_method('DoReportRtsFailed', 
                   'void', 
                   [param('ns3::WifiRemoteStation *', 'station')], 
                   is_pure_virtual=True, visibility='private', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::DoReportDataFailed(ns3::WifiRemoteStation * station) [member function]
    cls.add_method('DoReportDataFailed', 
                   'void', 
                   [param('ns3::WifiRemoteStation *', 'station')], 
                   is_pure_virtual=True, visibility='private', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::DoReportRtsOk(ns3::WifiRemoteStation * station, double ctsSnr, ns3::WifiMode ctsMode, double rtsSnr) [member function]
    cls.add_method('DoReportRtsOk', 
                   'void', 
                   [param('ns3::WifiRemoteStation *', 'station'), param('double', 'ctsSnr'), param('ns3::WifiMode', 'ctsMode'), param('double', 'rtsSnr')], 
                   is_pure_virtual=True, visibility='private', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::DoReportDataOk(ns3::WifiRemoteStation * station, double ackSnr, ns3::WifiMode ackMode, double dataSnr) [member function]
    cls.add_method('DoReportDataOk', 
                   'void', 
                   [param('ns3::WifiRemoteStation *', 'station'), param('double', 'ackSnr'), param('ns3::WifiMode', 'ackMode'), param('double', 'dataSnr')], 
                   is_pure_virtual=True, visibility='private', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::DoReportFinalRtsFailed(ns3::WifiRemoteStation * station) [member function]
    cls.add_method('DoReportFinalRtsFailed', 
                   'void', 
                   [param('ns3::WifiRemoteStation *', 'station')], 
                   is_pure_virtual=True, visibility='private', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::DoReportFinalDataFailed(ns3::WifiRemoteStation * station) [member function]
    cls.add_method('DoReportFinalDataFailed', 
                   'void', 
                   [param('ns3::WifiRemoteStation *', 'station')], 
                   is_pure_virtual=True, visibility='private', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::DoReportRxOk(ns3::WifiRemoteStation * station, double rxSnr, ns3::WifiMode txMode) [member function]
    cls.add_method('DoReportRxOk', 
                   'void', 
                   [param('ns3::WifiRemoteStation *', 'station'), param('double', 'rxSnr'), param('ns3::WifiMode', 'txMode')], 
                   is_pure_virtual=True, visibility='private', is_virtual=True)
    ## wifi-remote-station-manager.h (module 'wifi'): void ns3::WifiRemoteStationManager::DoReportAmpduTxStatus(ns3::WifiRemoteStation * station, uint8_t nSuccessfulMpdus, uint8_t nFailedMpdus, double rxSnr, double dataSnr) [member function]
    cls.add_method('DoReportAmpduTxStatus', 
                   'void', 
                   [param('ns3::WifiRemoteStation *', 'station'), param('uint8_t', 'nSuccessfulMpdus'), param('uint8_t', 'nFailedMpdus'), param('double', 'rxSnr'), param('double', 'dataSnr')], 
                   visibility='private', is_virtual=True)
    return

def register_Ns3ZetaRandomVariable_methods(root_module, cls):
    ## random-variable-stream.h (module 'core'): static ns3::TypeId ns3::ZetaRandomVariable::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## random-variable-stream.h (module 'core'): ns3::ZetaRandomVariable::ZetaRandomVariable() [constructor]
    cls.add_constructor([])
    ## random-variable-stream.h (module 'core'): double ns3::ZetaRandomVariable::GetAlpha() const [member function]
    cls.add_method('GetAlpha', 
                   'double', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::ZetaRandomVariable::GetValue(double alpha) [member function]
    cls.add_method('GetValue', 
                   'double', 
                   [param('double', 'alpha')])
    ## random-variable-stream.h (module 'core'): uint32_t ns3::ZetaRandomVariable::GetInteger(uint32_t alpha) [member function]
    cls.add_method('GetInteger', 
                   'uint32_t', 
                   [param('uint32_t', 'alpha')])
    ## random-variable-stream.h (module 'core'): double ns3::ZetaRandomVariable::GetValue() [member function]
    cls.add_method('GetValue', 
                   'double', 
                   [], 
                   is_virtual=True)
    ## random-variable-stream.h (module 'core'): uint32_t ns3::ZetaRandomVariable::GetInteger() [member function]
    cls.add_method('GetInteger', 
                   'uint32_t', 
                   [], 
                   is_virtual=True)
    return

def register_Ns3ZipfRandomVariable_methods(root_module, cls):
    ## random-variable-stream.h (module 'core'): static ns3::TypeId ns3::ZipfRandomVariable::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## random-variable-stream.h (module 'core'): ns3::ZipfRandomVariable::ZipfRandomVariable() [constructor]
    cls.add_constructor([])
    ## random-variable-stream.h (module 'core'): uint32_t ns3::ZipfRandomVariable::GetN() const [member function]
    cls.add_method('GetN', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::ZipfRandomVariable::GetAlpha() const [member function]
    cls.add_method('GetAlpha', 
                   'double', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::ZipfRandomVariable::GetValue(uint32_t n, double alpha) [member function]
    cls.add_method('GetValue', 
                   'double', 
                   [param('uint32_t', 'n'), param('double', 'alpha')])
    ## random-variable-stream.h (module 'core'): uint32_t ns3::ZipfRandomVariable::GetInteger(uint32_t n, uint32_t alpha) [member function]
    cls.add_method('GetInteger', 
                   'uint32_t', 
                   [param('uint32_t', 'n'), param('uint32_t', 'alpha')])
    ## random-variable-stream.h (module 'core'): double ns3::ZipfRandomVariable::GetValue() [member function]
    cls.add_method('GetValue', 
                   'double', 
                   [], 
                   is_virtual=True)
    ## random-variable-stream.h (module 'core'): uint32_t ns3::ZipfRandomVariable::GetInteger() [member function]
    cls.add_method('GetInteger', 
                   'uint32_t', 
                   [], 
                   is_virtual=True)
    return

def register_Ns3ArpCache_methods(root_module, cls):
    ## arp-cache.h (module 'internet'): ns3::ArpCache::ArpCache() [constructor]
    cls.add_constructor([])
    ## arp-cache.h (module 'internet'): ns3::ArpCache::Entry * ns3::ArpCache::Add(ns3::Ipv4Address to) [member function]
    cls.add_method('Add', 
                   'ns3::ArpCache::Entry *', 
                   [param('ns3::Ipv4Address', 'to')])
    ## arp-cache.h (module 'internet'): void ns3::ArpCache::Flush() [member function]
    cls.add_method('Flush', 
                   'void', 
                   [])
    ## arp-cache.h (module 'internet'): ns3::Time ns3::ArpCache::GetAliveTimeout() const [member function]
    cls.add_method('GetAliveTimeout', 
                   'ns3::Time', 
                   [], 
                   is_const=True)
    ## arp-cache.h (module 'internet'): ns3::Time ns3::ArpCache::GetDeadTimeout() const [member function]
    cls.add_method('GetDeadTimeout', 
                   'ns3::Time', 
                   [], 
                   is_const=True)
    ## arp-cache.h (module 'internet'): ns3::Ptr<ns3::NetDevice> ns3::ArpCache::GetDevice() const [member function]
    cls.add_method('GetDevice', 
                   'ns3::Ptr< ns3::NetDevice >', 
                   [], 
                   is_const=True)
    ## arp-cache.h (module 'internet'): ns3::Ptr<ns3::Ipv4Interface> ns3::ArpCache::GetInterface() const [member function]
    cls.add_method('GetInterface', 
                   'ns3::Ptr< ns3::Ipv4Interface >', 
                   [], 
                   is_const=True)
    ## arp-cache.h (module 'internet'): static ns3::TypeId ns3::ArpCache::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## arp-cache.h (module 'internet'): ns3::Time ns3::ArpCache::GetWaitReplyTimeout() const [member function]
    cls.add_method('GetWaitReplyTimeout', 
                   'ns3::Time', 
                   [], 
                   is_const=True)
    ## arp-cache.h (module 'internet'): ns3::ArpCache::Entry * ns3::ArpCache::Lookup(ns3::Ipv4Address destination) [member function]
    cls.add_method('Lookup', 
                   'ns3::ArpCache::Entry *', 
                   [param('ns3::Ipv4Address', 'destination')])
    ## arp-cache.h (module 'internet'): std::list<ns3::ArpCache::Entry *, std::allocator<ns3::ArpCache::Entry *> > ns3::ArpCache::LookupInverse(ns3::Address destination) [member function]
    cls.add_method('LookupInverse', 
                   'std::list< ns3::ArpCache::Entry * >', 
                   [param('ns3::Address', 'destination')])
    ## arp-cache.h (module 'internet'): void ns3::ArpCache::PrintArpCache(ns3::Ptr<ns3::OutputStreamWrapper> stream) [member function]
    cls.add_method('PrintArpCache', 
                   'void', 
                   [param('ns3::Ptr< ns3::OutputStreamWrapper >', 'stream')])
    ## arp-cache.h (module 'internet'): void ns3::ArpCache::Remove(ns3::ArpCache::Entry * entry) [member function]
    cls.add_method('Remove', 
                   'void', 
                   [param('ns3::ArpCache::Entry *', 'entry')])
    ## arp-cache.h (module 'internet'): void ns3::ArpCache::SetAliveTimeout(ns3::Time aliveTimeout) [member function]
    cls.add_method('SetAliveTimeout', 
                   'void', 
                   [param('ns3::Time', 'aliveTimeout')])
    ## arp-cache.h (module 'internet'): void ns3::ArpCache::SetArpRequestCallback(ns3::Callback<void, ns3::Ptr<const ns3::ArpCache>, ns3::Ipv4Address, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> arpRequestCallback) [member function]
    cls.add_method('SetArpRequestCallback', 
                   'void', 
                   [param('ns3::Callback< void, ns3::Ptr< ns3::ArpCache const >, ns3::Ipv4Address, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'arpRequestCallback')])
    ## arp-cache.h (module 'internet'): void ns3::ArpCache::SetDeadTimeout(ns3::Time deadTimeout) [member function]
    cls.add_method('SetDeadTimeout', 
                   'void', 
                   [param('ns3::Time', 'deadTimeout')])
    ## arp-cache.h (module 'internet'): void ns3::ArpCache::SetDevice(ns3::Ptr<ns3::NetDevice> device, ns3::Ptr<ns3::Ipv4Interface> interface) [member function]
    cls.add_method('SetDevice', 
                   'void', 
                   [param('ns3::Ptr< ns3::NetDevice >', 'device'), param('ns3::Ptr< ns3::Ipv4Interface >', 'interface')])
    ## arp-cache.h (module 'internet'): void ns3::ArpCache::SetWaitReplyTimeout(ns3::Time waitReplyTimeout) [member function]
    cls.add_method('SetWaitReplyTimeout', 
                   'void', 
                   [param('ns3::Time', 'waitReplyTimeout')])
    ## arp-cache.h (module 'internet'): void ns3::ArpCache::StartWaitReplyTimer() [member function]
    cls.add_method('StartWaitReplyTimer', 
                   'void', 
                   [])
    ## arp-cache.h (module 'internet'): void ns3::ArpCache::DoDispose() [member function]
    cls.add_method('DoDispose', 
                   'void', 
                   [], 
                   visibility='private', is_virtual=True)
    return

def register_Ns3ArpCacheEntry_methods(root_module, cls):
    ## arp-cache.h (module 'internet'): ns3::ArpCache::Entry::Entry(ns3::ArpCache::Entry const & arg0) [constructor]
    cls.add_constructor([param('ns3::ArpCache::Entry const &', 'arg0')])
    ## arp-cache.h (module 'internet'): ns3::ArpCache::Entry::Entry(ns3::ArpCache * arp) [constructor]
    cls.add_constructor([param('ns3::ArpCache *', 'arp')])
    ## arp-cache.h (module 'internet'): void ns3::ArpCache::Entry::ClearPendingPacket() [member function]
    cls.add_method('ClearPendingPacket', 
                   'void', 
                   [])
    ## arp-cache.h (module 'internet'): void ns3::ArpCache::Entry::ClearRetries() [member function]
    cls.add_method('ClearRetries', 
                   'void', 
                   [])
    ## arp-cache.h (module 'internet'): ns3::ArpCache::Ipv4PayloadHeaderPair ns3::ArpCache::Entry::DequeuePending() [member function]
    cls.add_method('DequeuePending', 
                   'ns3::ArpCache::Ipv4PayloadHeaderPair', 
                   [])
    ## arp-cache.h (module 'internet'): ns3::Ipv4Address ns3::ArpCache::Entry::GetIpv4Address() const [member function]
    cls.add_method('GetIpv4Address', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## arp-cache.h (module 'internet'): ns3::Address ns3::ArpCache::Entry::GetMacAddress() const [member function]
    cls.add_method('GetMacAddress', 
                   'ns3::Address', 
                   [], 
                   is_const=True)
    ## arp-cache.h (module 'internet'): uint32_t ns3::ArpCache::Entry::GetRetries() const [member function]
    cls.add_method('GetRetries', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## arp-cache.h (module 'internet'): void ns3::ArpCache::Entry::IncrementRetries() [member function]
    cls.add_method('IncrementRetries', 
                   'void', 
                   [])
    ## arp-cache.h (module 'internet'): bool ns3::ArpCache::Entry::IsAlive() [member function]
    cls.add_method('IsAlive', 
                   'bool', 
                   [])
    ## arp-cache.h (module 'internet'): bool ns3::ArpCache::Entry::IsDead() [member function]
    cls.add_method('IsDead', 
                   'bool', 
                   [])
    ## arp-cache.h (module 'internet'): bool ns3::ArpCache::Entry::IsExpired() const [member function]
    cls.add_method('IsExpired', 
                   'bool', 
                   [], 
                   is_const=True)
    ## arp-cache.h (module 'internet'): bool ns3::ArpCache::Entry::IsPermanent() [member function]
    cls.add_method('IsPermanent', 
                   'bool', 
                   [])
    ## arp-cache.h (module 'internet'): bool ns3::ArpCache::Entry::IsWaitReply() [member function]
    cls.add_method('IsWaitReply', 
                   'bool', 
                   [])
    ## arp-cache.h (module 'internet'): void ns3::ArpCache::Entry::MarkAlive(ns3::Address macAddress) [member function]
    cls.add_method('MarkAlive', 
                   'void', 
                   [param('ns3::Address', 'macAddress')])
    ## arp-cache.h (module 'internet'): void ns3::ArpCache::Entry::MarkDead() [member function]
    cls.add_method('MarkDead', 
                   'void', 
                   [])
    ## arp-cache.h (module 'internet'): void ns3::ArpCache::Entry::MarkPermanent() [member function]
    cls.add_method('MarkPermanent', 
                   'void', 
                   [])
    ## arp-cache.h (module 'internet'): void ns3::ArpCache::Entry::MarkWaitReply(ns3::ArpCache::Ipv4PayloadHeaderPair waiting) [member function]
    cls.add_method('MarkWaitReply', 
                   'void', 
                   [param('std::pair< ns3::Ptr< ns3::Packet >, ns3::Ipv4Header >', 'waiting')])
    ## arp-cache.h (module 'internet'): void ns3::ArpCache::Entry::SetIpv4Address(ns3::Ipv4Address destination) [member function]
    cls.add_method('SetIpv4Address', 
                   'void', 
                   [param('ns3::Ipv4Address', 'destination')])
    ## arp-cache.h (module 'internet'): void ns3::ArpCache::Entry::SetMacAddress(ns3::Address macAddress) [member function]
    cls.add_method('SetMacAddress', 
                   'void', 
                   [param('ns3::Address', 'macAddress')])
    ## arp-cache.h (module 'internet'): void ns3::ArpCache::Entry::SetMacAddresss(ns3::Address macAddress) [member function]
    cls.add_method('SetMacAddresss', 
                   'void', 
                   [param('ns3::Address', 'macAddress')], 
                   deprecated=True)
    ## arp-cache.h (module 'internet'): void ns3::ArpCache::Entry::UpdateSeen() [member function]
    cls.add_method('UpdateSeen', 
                   'void', 
                   [])
    ## arp-cache.h (module 'internet'): bool ns3::ArpCache::Entry::UpdateWaitReply(ns3::ArpCache::Ipv4PayloadHeaderPair waiting) [member function]
    cls.add_method('UpdateWaitReply', 
                   'bool', 
                   [param('std::pair< ns3::Ptr< ns3::Packet >, ns3::Ipv4Header >', 'waiting')])
    return

def register_Ns3AttributeAccessor_methods(root_module, cls):
    ## attribute.h (module 'core'): ns3::AttributeAccessor::AttributeAccessor(ns3::AttributeAccessor const & arg0) [constructor]
    cls.add_constructor([param('ns3::AttributeAccessor const &', 'arg0')])
    ## attribute.h (module 'core'): ns3::AttributeAccessor::AttributeAccessor() [constructor]
    cls.add_constructor([])
    ## attribute.h (module 'core'): bool ns3::AttributeAccessor::Get(ns3::ObjectBase const * object, ns3::AttributeValue & attribute) const [member function]
    cls.add_method('Get', 
                   'bool', 
                   [param('ns3::ObjectBase const *', 'object'), param('ns3::AttributeValue &', 'attribute')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## attribute.h (module 'core'): bool ns3::AttributeAccessor::HasGetter() const [member function]
    cls.add_method('HasGetter', 
                   'bool', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## attribute.h (module 'core'): bool ns3::AttributeAccessor::HasSetter() const [member function]
    cls.add_method('HasSetter', 
                   'bool', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## attribute.h (module 'core'): bool ns3::AttributeAccessor::Set(ns3::ObjectBase * object, ns3::AttributeValue const & value) const [member function]
    cls.add_method('Set', 
                   'bool', 
                   [param('ns3::ObjectBase *', 'object', transfer_ownership=False), param('ns3::AttributeValue const &', 'value')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    return

def register_Ns3AttributeChecker_methods(root_module, cls):
    ## attribute.h (module 'core'): ns3::AttributeChecker::AttributeChecker(ns3::AttributeChecker const & arg0) [constructor]
    cls.add_constructor([param('ns3::AttributeChecker const &', 'arg0')])
    ## attribute.h (module 'core'): ns3::AttributeChecker::AttributeChecker() [constructor]
    cls.add_constructor([])
    ## attribute.h (module 'core'): bool ns3::AttributeChecker::Check(ns3::AttributeValue const & value) const [member function]
    cls.add_method('Check', 
                   'bool', 
                   [param('ns3::AttributeValue const &', 'value')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## attribute.h (module 'core'): bool ns3::AttributeChecker::Copy(ns3::AttributeValue const & source, ns3::AttributeValue & destination) const [member function]
    cls.add_method('Copy', 
                   'bool', 
                   [param('ns3::AttributeValue const &', 'source'), param('ns3::AttributeValue &', 'destination')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## attribute.h (module 'core'): ns3::Ptr<ns3::AttributeValue> ns3::AttributeChecker::Create() const [member function]
    cls.add_method('Create', 
                   'ns3::Ptr< ns3::AttributeValue >', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## attribute.h (module 'core'): ns3::Ptr<ns3::AttributeValue> ns3::AttributeChecker::CreateValidValue(ns3::AttributeValue const & value) const [member function]
    cls.add_method('CreateValidValue', 
                   'ns3::Ptr< ns3::AttributeValue >', 
                   [param('ns3::AttributeValue const &', 'value')], 
                   is_const=True)
    ## attribute.h (module 'core'): std::string ns3::AttributeChecker::GetUnderlyingTypeInformation() const [member function]
    cls.add_method('GetUnderlyingTypeInformation', 
                   'std::string', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## attribute.h (module 'core'): std::string ns3::AttributeChecker::GetValueTypeName() const [member function]
    cls.add_method('GetValueTypeName', 
                   'std::string', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## attribute.h (module 'core'): bool ns3::AttributeChecker::HasUnderlyingTypeInformation() const [member function]
    cls.add_method('HasUnderlyingTypeInformation', 
                   'bool', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    return

def register_Ns3AttributeValue_methods(root_module, cls):
    ## attribute.h (module 'core'): ns3::AttributeValue::AttributeValue(ns3::AttributeValue const & arg0) [constructor]
    cls.add_constructor([param('ns3::AttributeValue const &', 'arg0')])
    ## attribute.h (module 'core'): ns3::AttributeValue::AttributeValue() [constructor]
    cls.add_constructor([])
    ## attribute.h (module 'core'): ns3::Ptr<ns3::AttributeValue> ns3::AttributeValue::Copy() const [member function]
    cls.add_method('Copy', 
                   'ns3::Ptr< ns3::AttributeValue >', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## attribute.h (module 'core'): bool ns3::AttributeValue::DeserializeFromString(std::string value, ns3::Ptr<const ns3::AttributeChecker> checker) [member function]
    cls.add_method('DeserializeFromString', 
                   'bool', 
                   [param('std::string', 'value'), param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_pure_virtual=True, is_virtual=True)
    ## attribute.h (module 'core'): std::string ns3::AttributeValue::SerializeToString(ns3::Ptr<const ns3::AttributeChecker> checker) const [member function]
    cls.add_method('SerializeToString', 
                   'std::string', 
                   [param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    return

def register_Ns3CallbackChecker_methods(root_module, cls):
    ## callback.h (module 'core'): ns3::CallbackChecker::CallbackChecker() [constructor]
    cls.add_constructor([])
    ## callback.h (module 'core'): ns3::CallbackChecker::CallbackChecker(ns3::CallbackChecker const & arg0) [constructor]
    cls.add_constructor([param('ns3::CallbackChecker const &', 'arg0')])
    return

def register_Ns3CallbackImplBase_methods(root_module, cls):
    ## callback.h (module 'core'): ns3::CallbackImplBase::CallbackImplBase() [constructor]
    cls.add_constructor([])
    ## callback.h (module 'core'): ns3::CallbackImplBase::CallbackImplBase(ns3::CallbackImplBase const & arg0) [constructor]
    cls.add_constructor([param('ns3::CallbackImplBase const &', 'arg0')])
    ## callback.h (module 'core'): std::string ns3::CallbackImplBase::GetTypeid() const [member function]
    cls.add_method('GetTypeid', 
                   'std::string', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## callback.h (module 'core'): bool ns3::CallbackImplBase::IsEqual(ns3::Ptr<const ns3::CallbackImplBase> other) const [member function]
    cls.add_method('IsEqual', 
                   'bool', 
                   [param('ns3::Ptr< ns3::CallbackImplBase const >', 'other')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## callback.h (module 'core'): static std::string ns3::CallbackImplBase::Demangle(std::string const & mangled) [member function]
    cls.add_method('Demangle', 
                   'std::string', 
                   [param('std::string const &', 'mangled')], 
                   is_static=True, visibility='protected')
    ## callback.h (module 'core'): static std::string ns3::CallbackImplBase::GetCppTypeid() [member function]
    cls.add_method('GetCppTypeid', 
                   'std::string', 
                   [], 
                   is_static=True, visibility='protected', template_parameters=[u'ns3::ObjectBase*'])
    ## callback.h (module 'core'): static std::string ns3::CallbackImplBase::GetCppTypeid() [member function]
    cls.add_method('GetCppTypeid', 
                   'std::string', 
                   [], 
                   is_static=True, visibility='protected', template_parameters=[u'void'])
    ## callback.h (module 'core'): static std::string ns3::CallbackImplBase::GetCppTypeid() [member function]
    cls.add_method('GetCppTypeid', 
                   'std::string', 
                   [], 
                   is_static=True, visibility='protected', template_parameters=[u'ns3::Ipv4Address'])
    ## callback.h (module 'core'): static std::string ns3::CallbackImplBase::GetCppTypeid() [member function]
    cls.add_method('GetCppTypeid', 
                   'std::string', 
                   [], 
                   is_static=True, visibility='protected', template_parameters=[u'unsigned char'])
    ## callback.h (module 'core'): static std::string ns3::CallbackImplBase::GetCppTypeid() [member function]
    cls.add_method('GetCppTypeid', 
                   'std::string', 
                   [], 
                   is_static=True, visibility='protected', template_parameters=[u'ns3::Ptr<ns3::Socket> '])
    ## callback.h (module 'core'): static std::string ns3::CallbackImplBase::GetCppTypeid() [member function]
    cls.add_method('GetCppTypeid', 
                   'std::string', 
                   [], 
                   is_static=True, visibility='protected', template_parameters=[u'bool'])
    ## callback.h (module 'core'): static std::string ns3::CallbackImplBase::GetCppTypeid() [member function]
    cls.add_method('GetCppTypeid', 
                   'std::string', 
                   [], 
                   is_static=True, visibility='protected', template_parameters=[u'ns3::Address const&'])
    ## callback.h (module 'core'): static std::string ns3::CallbackImplBase::GetCppTypeid() [member function]
    cls.add_method('GetCppTypeid', 
                   'std::string', 
                   [], 
                   is_static=True, visibility='protected', template_parameters=[u'unsigned int'])
    ## callback.h (module 'core'): static std::string ns3::CallbackImplBase::GetCppTypeid() [member function]
    cls.add_method('GetCppTypeid', 
                   'std::string', 
                   [], 
                   is_static=True, visibility='protected', template_parameters=[u'ns3::Ptr<ns3::NetDevice> '])
    ## callback.h (module 'core'): static std::string ns3::CallbackImplBase::GetCppTypeid() [member function]
    cls.add_method('GetCppTypeid', 
                   'std::string', 
                   [], 
                   is_static=True, visibility='protected', template_parameters=[u'ns3::Ptr<ns3::Packet const> '])
    ## callback.h (module 'core'): static std::string ns3::CallbackImplBase::GetCppTypeid() [member function]
    cls.add_method('GetCppTypeid', 
                   'std::string', 
                   [], 
                   is_static=True, visibility='protected', template_parameters=[u'unsigned short'])
    ## callback.h (module 'core'): static std::string ns3::CallbackImplBase::GetCppTypeid() [member function]
    cls.add_method('GetCppTypeid', 
                   'std::string', 
                   [], 
                   is_static=True, visibility='protected', template_parameters=[u'ns3::NetDevice::PacketType'])
    ## callback.h (module 'core'): static std::string ns3::CallbackImplBase::GetCppTypeid() [member function]
    cls.add_method('GetCppTypeid', 
                   'std::string', 
                   [], 
                   is_static=True, visibility='protected', template_parameters=[u'ns3::Ipv4Header const&'])
    ## callback.h (module 'core'): static std::string ns3::CallbackImplBase::GetCppTypeid() [member function]
    cls.add_method('GetCppTypeid', 
                   'std::string', 
                   [], 
                   is_static=True, visibility='protected', template_parameters=[u'ns3::Ptr<ns3::Ipv4> '])
    ## callback.h (module 'core'): static std::string ns3::CallbackImplBase::GetCppTypeid() [member function]
    cls.add_method('GetCppTypeid', 
                   'std::string', 
                   [], 
                   is_static=True, visibility='protected', template_parameters=[u'ns3::Ipv4L3Protocol::DropReason'])
    ## callback.h (module 'core'): static std::string ns3::CallbackImplBase::GetCppTypeid() [member function]
    cls.add_method('GetCppTypeid', 
                   'std::string', 
                   [], 
                   is_static=True, visibility='protected', template_parameters=[u'ns3::Ptr<ns3::Packet> '])
    ## callback.h (module 'core'): static std::string ns3::CallbackImplBase::GetCppTypeid() [member function]
    cls.add_method('GetCppTypeid', 
                   'std::string', 
                   [], 
                   is_static=True, visibility='protected', template_parameters=[u'ns3::Ptr<ns3::Ipv4Route> '])
    ## callback.h (module 'core'): static std::string ns3::CallbackImplBase::GetCppTypeid() [member function]
    cls.add_method('GetCppTypeid', 
                   'std::string', 
                   [], 
                   is_static=True, visibility='protected', template_parameters=[u'ns3::Mac48Address'])
    ## callback.h (module 'core'): static std::string ns3::CallbackImplBase::GetCppTypeid() [member function]
    cls.add_method('GetCppTypeid', 
                   'std::string', 
                   [], 
                   is_static=True, visibility='protected', template_parameters=[u'ns3::rushattackdsr::RushattackdsrOptionSRHeader const&'])
    return

def register_Ns3CallbackValue_methods(root_module, cls):
    ## callback.h (module 'core'): ns3::CallbackValue::CallbackValue(ns3::CallbackValue const & arg0) [constructor]
    cls.add_constructor([param('ns3::CallbackValue const &', 'arg0')])
    ## callback.h (module 'core'): ns3::CallbackValue::CallbackValue() [constructor]
    cls.add_constructor([])
    ## callback.h (module 'core'): ns3::CallbackValue::CallbackValue(ns3::CallbackBase const & base) [constructor]
    cls.add_constructor([param('ns3::CallbackBase const &', 'base')])
    ## callback.h (module 'core'): ns3::Ptr<ns3::AttributeValue> ns3::CallbackValue::Copy() const [member function]
    cls.add_method('Copy', 
                   'ns3::Ptr< ns3::AttributeValue >', 
                   [], 
                   is_const=True, is_virtual=True)
    ## callback.h (module 'core'): bool ns3::CallbackValue::DeserializeFromString(std::string value, ns3::Ptr<const ns3::AttributeChecker> checker) [member function]
    cls.add_method('DeserializeFromString', 
                   'bool', 
                   [param('std::string', 'value'), param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_virtual=True)
    ## callback.h (module 'core'): std::string ns3::CallbackValue::SerializeToString(ns3::Ptr<const ns3::AttributeChecker> checker) const [member function]
    cls.add_method('SerializeToString', 
                   'std::string', 
                   [param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_const=True, is_virtual=True)
    ## callback.h (module 'core'): void ns3::CallbackValue::Set(ns3::CallbackBase base) [member function]
    cls.add_method('Set', 
                   'void', 
                   [param('ns3::CallbackBase', 'base')])
    return

def register_Ns3ConstantRandomVariable_methods(root_module, cls):
    ## random-variable-stream.h (module 'core'): static ns3::TypeId ns3::ConstantRandomVariable::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## random-variable-stream.h (module 'core'): ns3::ConstantRandomVariable::ConstantRandomVariable() [constructor]
    cls.add_constructor([])
    ## random-variable-stream.h (module 'core'): double ns3::ConstantRandomVariable::GetConstant() const [member function]
    cls.add_method('GetConstant', 
                   'double', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::ConstantRandomVariable::GetValue(double constant) [member function]
    cls.add_method('GetValue', 
                   'double', 
                   [param('double', 'constant')])
    ## random-variable-stream.h (module 'core'): uint32_t ns3::ConstantRandomVariable::GetInteger(uint32_t constant) [member function]
    cls.add_method('GetInteger', 
                   'uint32_t', 
                   [param('uint32_t', 'constant')])
    ## random-variable-stream.h (module 'core'): double ns3::ConstantRandomVariable::GetValue() [member function]
    cls.add_method('GetValue', 
                   'double', 
                   [], 
                   is_virtual=True)
    ## random-variable-stream.h (module 'core'): uint32_t ns3::ConstantRandomVariable::GetInteger() [member function]
    cls.add_method('GetInteger', 
                   'uint32_t', 
                   [], 
                   is_virtual=True)
    return

def register_Ns3DataRateChecker_methods(root_module, cls):
    ## data-rate.h (module 'network'): ns3::DataRateChecker::DataRateChecker() [constructor]
    cls.add_constructor([])
    ## data-rate.h (module 'network'): ns3::DataRateChecker::DataRateChecker(ns3::DataRateChecker const & arg0) [constructor]
    cls.add_constructor([param('ns3::DataRateChecker const &', 'arg0')])
    return

def register_Ns3DataRateValue_methods(root_module, cls):
    ## data-rate.h (module 'network'): ns3::DataRateValue::DataRateValue() [constructor]
    cls.add_constructor([])
    ## data-rate.h (module 'network'): ns3::DataRateValue::DataRateValue(ns3::DataRate const & value) [constructor]
    cls.add_constructor([param('ns3::DataRate const &', 'value')])
    ## data-rate.h (module 'network'): ns3::DataRateValue::DataRateValue(ns3::DataRateValue const & arg0) [constructor]
    cls.add_constructor([param('ns3::DataRateValue const &', 'arg0')])
    ## data-rate.h (module 'network'): ns3::Ptr<ns3::AttributeValue> ns3::DataRateValue::Copy() const [member function]
    cls.add_method('Copy', 
                   'ns3::Ptr< ns3::AttributeValue >', 
                   [], 
                   is_const=True, is_virtual=True)
    ## data-rate.h (module 'network'): bool ns3::DataRateValue::DeserializeFromString(std::string value, ns3::Ptr<const ns3::AttributeChecker> checker) [member function]
    cls.add_method('DeserializeFromString', 
                   'bool', 
                   [param('std::string', 'value'), param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_virtual=True)
    ## data-rate.h (module 'network'): ns3::DataRate ns3::DataRateValue::Get() const [member function]
    cls.add_method('Get', 
                   'ns3::DataRate', 
                   [], 
                   is_const=True)
    ## data-rate.h (module 'network'): std::string ns3::DataRateValue::SerializeToString(ns3::Ptr<const ns3::AttributeChecker> checker) const [member function]
    cls.add_method('SerializeToString', 
                   'std::string', 
                   [param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_const=True, is_virtual=True)
    ## data-rate.h (module 'network'): void ns3::DataRateValue::Set(ns3::DataRate const & value) [member function]
    cls.add_method('Set', 
                   'void', 
                   [param('ns3::DataRate const &', 'value')])
    return

def register_Ns3DeterministicRandomVariable_methods(root_module, cls):
    ## random-variable-stream.h (module 'core'): static ns3::TypeId ns3::DeterministicRandomVariable::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## random-variable-stream.h (module 'core'): ns3::DeterministicRandomVariable::DeterministicRandomVariable() [constructor]
    cls.add_constructor([])
    ## random-variable-stream.h (module 'core'): void ns3::DeterministicRandomVariable::SetValueArray(double * values, std::size_t length) [member function]
    cls.add_method('SetValueArray', 
                   'void', 
                   [param('double *', 'values'), param('std::size_t', 'length')])
    ## random-variable-stream.h (module 'core'): double ns3::DeterministicRandomVariable::GetValue() [member function]
    cls.add_method('GetValue', 
                   'double', 
                   [], 
                   is_virtual=True)
    ## random-variable-stream.h (module 'core'): uint32_t ns3::DeterministicRandomVariable::GetInteger() [member function]
    cls.add_method('GetInteger', 
                   'uint32_t', 
                   [], 
                   is_virtual=True)
    return

def register_Ns3EmpiricalRandomVariable_methods(root_module, cls):
    ## random-variable-stream.h (module 'core'): ns3::EmpiricalRandomVariable::EmpiricalRandomVariable() [constructor]
    cls.add_constructor([])
    ## random-variable-stream.h (module 'core'): void ns3::EmpiricalRandomVariable::CDF(double v, double c) [member function]
    cls.add_method('CDF', 
                   'void', 
                   [param('double', 'v'), param('double', 'c')])
    ## random-variable-stream.h (module 'core'): uint32_t ns3::EmpiricalRandomVariable::GetInteger() [member function]
    cls.add_method('GetInteger', 
                   'uint32_t', 
                   [], 
                   is_virtual=True)
    ## random-variable-stream.h (module 'core'): static ns3::TypeId ns3::EmpiricalRandomVariable::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## random-variable-stream.h (module 'core'): double ns3::EmpiricalRandomVariable::GetValue() [member function]
    cls.add_method('GetValue', 
                   'double', 
                   [], 
                   is_virtual=True)
    ## random-variable-stream.h (module 'core'): double ns3::EmpiricalRandomVariable::Interpolate(double c1, double c2, double v1, double v2, double r) [member function]
    cls.add_method('Interpolate', 
                   'double', 
                   [param('double', 'c1'), param('double', 'c2'), param('double', 'v1'), param('double', 'v2'), param('double', 'r')], 
                   visibility='private', is_virtual=True)
    ## random-variable-stream.h (module 'core'): void ns3::EmpiricalRandomVariable::Validate() [member function]
    cls.add_method('Validate', 
                   'void', 
                   [], 
                   visibility='private', is_virtual=True)
    return

def register_Ns3EmptyAttributeAccessor_methods(root_module, cls):
    ## attribute.h (module 'core'): ns3::EmptyAttributeAccessor::EmptyAttributeAccessor(ns3::EmptyAttributeAccessor const & arg0) [constructor]
    cls.add_constructor([param('ns3::EmptyAttributeAccessor const &', 'arg0')])
    ## attribute.h (module 'core'): ns3::EmptyAttributeAccessor::EmptyAttributeAccessor() [constructor]
    cls.add_constructor([])
    ## attribute.h (module 'core'): bool ns3::EmptyAttributeAccessor::Get(ns3::ObjectBase const * object, ns3::AttributeValue & attribute) const [member function]
    cls.add_method('Get', 
                   'bool', 
                   [param('ns3::ObjectBase const *', 'object'), param('ns3::AttributeValue &', 'attribute')], 
                   is_const=True, is_virtual=True)
    ## attribute.h (module 'core'): bool ns3::EmptyAttributeAccessor::HasGetter() const [member function]
    cls.add_method('HasGetter', 
                   'bool', 
                   [], 
                   is_const=True, is_virtual=True)
    ## attribute.h (module 'core'): bool ns3::EmptyAttributeAccessor::HasSetter() const [member function]
    cls.add_method('HasSetter', 
                   'bool', 
                   [], 
                   is_const=True, is_virtual=True)
    ## attribute.h (module 'core'): bool ns3::EmptyAttributeAccessor::Set(ns3::ObjectBase * object, ns3::AttributeValue const & value) const [member function]
    cls.add_method('Set', 
                   'bool', 
                   [param('ns3::ObjectBase *', 'object'), param('ns3::AttributeValue const &', 'value')], 
                   is_const=True, is_virtual=True)
    return

def register_Ns3EmptyAttributeChecker_methods(root_module, cls):
    ## attribute.h (module 'core'): ns3::EmptyAttributeChecker::EmptyAttributeChecker(ns3::EmptyAttributeChecker const & arg0) [constructor]
    cls.add_constructor([param('ns3::EmptyAttributeChecker const &', 'arg0')])
    ## attribute.h (module 'core'): ns3::EmptyAttributeChecker::EmptyAttributeChecker() [constructor]
    cls.add_constructor([])
    ## attribute.h (module 'core'): bool ns3::EmptyAttributeChecker::Check(ns3::AttributeValue const & value) const [member function]
    cls.add_method('Check', 
                   'bool', 
                   [param('ns3::AttributeValue const &', 'value')], 
                   is_const=True, is_virtual=True)
    ## attribute.h (module 'core'): bool ns3::EmptyAttributeChecker::Copy(ns3::AttributeValue const & source, ns3::AttributeValue & destination) const [member function]
    cls.add_method('Copy', 
                   'bool', 
                   [param('ns3::AttributeValue const &', 'source'), param('ns3::AttributeValue &', 'destination')], 
                   is_const=True, is_virtual=True)
    ## attribute.h (module 'core'): ns3::Ptr<ns3::AttributeValue> ns3::EmptyAttributeChecker::Create() const [member function]
    cls.add_method('Create', 
                   'ns3::Ptr< ns3::AttributeValue >', 
                   [], 
                   is_const=True, is_virtual=True)
    ## attribute.h (module 'core'): std::string ns3::EmptyAttributeChecker::GetUnderlyingTypeInformation() const [member function]
    cls.add_method('GetUnderlyingTypeInformation', 
                   'std::string', 
                   [], 
                   is_const=True, is_virtual=True)
    ## attribute.h (module 'core'): std::string ns3::EmptyAttributeChecker::GetValueTypeName() const [member function]
    cls.add_method('GetValueTypeName', 
                   'std::string', 
                   [], 
                   is_const=True, is_virtual=True)
    ## attribute.h (module 'core'): bool ns3::EmptyAttributeChecker::HasUnderlyingTypeInformation() const [member function]
    cls.add_method('HasUnderlyingTypeInformation', 
                   'bool', 
                   [], 
                   is_const=True, is_virtual=True)
    return

def register_Ns3EmptyAttributeValue_methods(root_module, cls):
    ## attribute.h (module 'core'): ns3::EmptyAttributeValue::EmptyAttributeValue(ns3::EmptyAttributeValue const & arg0) [constructor]
    cls.add_constructor([param('ns3::EmptyAttributeValue const &', 'arg0')])
    ## attribute.h (module 'core'): ns3::EmptyAttributeValue::EmptyAttributeValue() [constructor]
    cls.add_constructor([])
    ## attribute.h (module 'core'): ns3::Ptr<ns3::AttributeValue> ns3::EmptyAttributeValue::Copy() const [member function]
    cls.add_method('Copy', 
                   'ns3::Ptr< ns3::AttributeValue >', 
                   [], 
                   is_const=True, visibility='private', is_virtual=True)
    ## attribute.h (module 'core'): bool ns3::EmptyAttributeValue::DeserializeFromString(std::string value, ns3::Ptr<const ns3::AttributeChecker> checker) [member function]
    cls.add_method('DeserializeFromString', 
                   'bool', 
                   [param('std::string', 'value'), param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   visibility='private', is_virtual=True)
    ## attribute.h (module 'core'): std::string ns3::EmptyAttributeValue::SerializeToString(ns3::Ptr<const ns3::AttributeChecker> checker) const [member function]
    cls.add_method('SerializeToString', 
                   'std::string', 
                   [param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_const=True, visibility='private', is_virtual=True)
    return

def register_Ns3EnumChecker_methods(root_module, cls):
    ## enum.h (module 'core'): ns3::EnumChecker::EnumChecker(ns3::EnumChecker const & arg0) [constructor]
    cls.add_constructor([param('ns3::EnumChecker const &', 'arg0')])
    ## enum.h (module 'core'): ns3::EnumChecker::EnumChecker() [constructor]
    cls.add_constructor([])
    ## enum.h (module 'core'): void ns3::EnumChecker::Add(int value, std::string name) [member function]
    cls.add_method('Add', 
                   'void', 
                   [param('int', 'value'), param('std::string', 'name')])
    ## enum.h (module 'core'): void ns3::EnumChecker::AddDefault(int value, std::string name) [member function]
    cls.add_method('AddDefault', 
                   'void', 
                   [param('int', 'value'), param('std::string', 'name')])
    ## enum.h (module 'core'): bool ns3::EnumChecker::Check(ns3::AttributeValue const & value) const [member function]
    cls.add_method('Check', 
                   'bool', 
                   [param('ns3::AttributeValue const &', 'value')], 
                   is_const=True, is_virtual=True)
    ## enum.h (module 'core'): bool ns3::EnumChecker::Copy(ns3::AttributeValue const & src, ns3::AttributeValue & dst) const [member function]
    cls.add_method('Copy', 
                   'bool', 
                   [param('ns3::AttributeValue const &', 'src'), param('ns3::AttributeValue &', 'dst')], 
                   is_const=True, is_virtual=True)
    ## enum.h (module 'core'): ns3::Ptr<ns3::AttributeValue> ns3::EnumChecker::Create() const [member function]
    cls.add_method('Create', 
                   'ns3::Ptr< ns3::AttributeValue >', 
                   [], 
                   is_const=True, is_virtual=True)
    ## enum.h (module 'core'): std::string ns3::EnumChecker::GetUnderlyingTypeInformation() const [member function]
    cls.add_method('GetUnderlyingTypeInformation', 
                   'std::string', 
                   [], 
                   is_const=True, is_virtual=True)
    ## enum.h (module 'core'): std::string ns3::EnumChecker::GetValueTypeName() const [member function]
    cls.add_method('GetValueTypeName', 
                   'std::string', 
                   [], 
                   is_const=True, is_virtual=True)
    ## enum.h (module 'core'): bool ns3::EnumChecker::HasUnderlyingTypeInformation() const [member function]
    cls.add_method('HasUnderlyingTypeInformation', 
                   'bool', 
                   [], 
                   is_const=True, is_virtual=True)
    return

def register_Ns3EnumValue_methods(root_module, cls):
    ## enum.h (module 'core'): ns3::EnumValue::EnumValue(ns3::EnumValue const & arg0) [constructor]
    cls.add_constructor([param('ns3::EnumValue const &', 'arg0')])
    ## enum.h (module 'core'): ns3::EnumValue::EnumValue() [constructor]
    cls.add_constructor([])
    ## enum.h (module 'core'): ns3::EnumValue::EnumValue(int value) [constructor]
    cls.add_constructor([param('int', 'value')])
    ## enum.h (module 'core'): ns3::Ptr<ns3::AttributeValue> ns3::EnumValue::Copy() const [member function]
    cls.add_method('Copy', 
                   'ns3::Ptr< ns3::AttributeValue >', 
                   [], 
                   is_const=True, is_virtual=True)
    ## enum.h (module 'core'): bool ns3::EnumValue::DeserializeFromString(std::string value, ns3::Ptr<const ns3::AttributeChecker> checker) [member function]
    cls.add_method('DeserializeFromString', 
                   'bool', 
                   [param('std::string', 'value'), param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_virtual=True)
    ## enum.h (module 'core'): int ns3::EnumValue::Get() const [member function]
    cls.add_method('Get', 
                   'int', 
                   [], 
                   is_const=True)
    ## enum.h (module 'core'): std::string ns3::EnumValue::SerializeToString(ns3::Ptr<const ns3::AttributeChecker> checker) const [member function]
    cls.add_method('SerializeToString', 
                   'std::string', 
                   [param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_const=True, is_virtual=True)
    ## enum.h (module 'core'): void ns3::EnumValue::Set(int value) [member function]
    cls.add_method('Set', 
                   'void', 
                   [param('int', 'value')])
    return

def register_Ns3ErlangRandomVariable_methods(root_module, cls):
    ## random-variable-stream.h (module 'core'): static ns3::TypeId ns3::ErlangRandomVariable::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## random-variable-stream.h (module 'core'): ns3::ErlangRandomVariable::ErlangRandomVariable() [constructor]
    cls.add_constructor([])
    ## random-variable-stream.h (module 'core'): uint32_t ns3::ErlangRandomVariable::GetK() const [member function]
    cls.add_method('GetK', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::ErlangRandomVariable::GetLambda() const [member function]
    cls.add_method('GetLambda', 
                   'double', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::ErlangRandomVariable::GetValue(uint32_t k, double lambda) [member function]
    cls.add_method('GetValue', 
                   'double', 
                   [param('uint32_t', 'k'), param('double', 'lambda')])
    ## random-variable-stream.h (module 'core'): uint32_t ns3::ErlangRandomVariable::GetInteger(uint32_t k, uint32_t lambda) [member function]
    cls.add_method('GetInteger', 
                   'uint32_t', 
                   [param('uint32_t', 'k'), param('uint32_t', 'lambda')])
    ## random-variable-stream.h (module 'core'): double ns3::ErlangRandomVariable::GetValue() [member function]
    cls.add_method('GetValue', 
                   'double', 
                   [], 
                   is_virtual=True)
    ## random-variable-stream.h (module 'core'): uint32_t ns3::ErlangRandomVariable::GetInteger() [member function]
    cls.add_method('GetInteger', 
                   'uint32_t', 
                   [], 
                   is_virtual=True)
    return

def register_Ns3EventImpl_methods(root_module, cls):
    ## event-impl.h (module 'core'): ns3::EventImpl::EventImpl(ns3::EventImpl const & arg0) [constructor]
    cls.add_constructor([param('ns3::EventImpl const &', 'arg0')])
    ## event-impl.h (module 'core'): ns3::EventImpl::EventImpl() [constructor]
    cls.add_constructor([])
    ## event-impl.h (module 'core'): void ns3::EventImpl::Cancel() [member function]
    cls.add_method('Cancel', 
                   'void', 
                   [])
    ## event-impl.h (module 'core'): void ns3::EventImpl::Invoke() [member function]
    cls.add_method('Invoke', 
                   'void', 
                   [])
    ## event-impl.h (module 'core'): bool ns3::EventImpl::IsCancelled() [member function]
    cls.add_method('IsCancelled', 
                   'bool', 
                   [])
    ## event-impl.h (module 'core'): void ns3::EventImpl::Notify() [member function]
    cls.add_method('Notify', 
                   'void', 
                   [], 
                   is_pure_virtual=True, visibility='protected', is_virtual=True)
    return

def register_Ns3ExponentialRandomVariable_methods(root_module, cls):
    ## random-variable-stream.h (module 'core'): static ns3::TypeId ns3::ExponentialRandomVariable::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## random-variable-stream.h (module 'core'): ns3::ExponentialRandomVariable::ExponentialRandomVariable() [constructor]
    cls.add_constructor([])
    ## random-variable-stream.h (module 'core'): double ns3::ExponentialRandomVariable::GetMean() const [member function]
    cls.add_method('GetMean', 
                   'double', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::ExponentialRandomVariable::GetBound() const [member function]
    cls.add_method('GetBound', 
                   'double', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::ExponentialRandomVariable::GetValue(double mean, double bound) [member function]
    cls.add_method('GetValue', 
                   'double', 
                   [param('double', 'mean'), param('double', 'bound')])
    ## random-variable-stream.h (module 'core'): uint32_t ns3::ExponentialRandomVariable::GetInteger(uint32_t mean, uint32_t bound) [member function]
    cls.add_method('GetInteger', 
                   'uint32_t', 
                   [param('uint32_t', 'mean'), param('uint32_t', 'bound')])
    ## random-variable-stream.h (module 'core'): double ns3::ExponentialRandomVariable::GetValue() [member function]
    cls.add_method('GetValue', 
                   'double', 
                   [], 
                   is_virtual=True)
    ## random-variable-stream.h (module 'core'): uint32_t ns3::ExponentialRandomVariable::GetInteger() [member function]
    cls.add_method('GetInteger', 
                   'uint32_t', 
                   [], 
                   is_virtual=True)
    return

def register_Ns3GammaRandomVariable_methods(root_module, cls):
    ## random-variable-stream.h (module 'core'): static ns3::TypeId ns3::GammaRandomVariable::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## random-variable-stream.h (module 'core'): ns3::GammaRandomVariable::GammaRandomVariable() [constructor]
    cls.add_constructor([])
    ## random-variable-stream.h (module 'core'): double ns3::GammaRandomVariable::GetAlpha() const [member function]
    cls.add_method('GetAlpha', 
                   'double', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::GammaRandomVariable::GetBeta() const [member function]
    cls.add_method('GetBeta', 
                   'double', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::GammaRandomVariable::GetValue(double alpha, double beta) [member function]
    cls.add_method('GetValue', 
                   'double', 
                   [param('double', 'alpha'), param('double', 'beta')])
    ## random-variable-stream.h (module 'core'): uint32_t ns3::GammaRandomVariable::GetInteger(uint32_t alpha, uint32_t beta) [member function]
    cls.add_method('GetInteger', 
                   'uint32_t', 
                   [param('uint32_t', 'alpha'), param('uint32_t', 'beta')])
    ## random-variable-stream.h (module 'core'): double ns3::GammaRandomVariable::GetValue() [member function]
    cls.add_method('GetValue', 
                   'double', 
                   [], 
                   is_virtual=True)
    ## random-variable-stream.h (module 'core'): uint32_t ns3::GammaRandomVariable::GetInteger() [member function]
    cls.add_method('GetInteger', 
                   'uint32_t', 
                   [], 
                   is_virtual=True)
    return

def register_Ns3IpL4Protocol_methods(root_module, cls):
    ## ip-l4-protocol.h (module 'internet'): ns3::IpL4Protocol::IpL4Protocol() [constructor]
    cls.add_constructor([])
    ## ip-l4-protocol.h (module 'internet'): ns3::IpL4Protocol::IpL4Protocol(ns3::IpL4Protocol const & arg0) [constructor]
    cls.add_constructor([param('ns3::IpL4Protocol const &', 'arg0')])
    ## ip-l4-protocol.h (module 'internet'): ns3::IpL4Protocol::DownTargetCallback ns3::IpL4Protocol::GetDownTarget() const [member function]
    cls.add_method('GetDownTarget', 
                   'ns3::IpL4Protocol::DownTargetCallback', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## ip-l4-protocol.h (module 'internet'): ns3::IpL4Protocol::DownTargetCallback6 ns3::IpL4Protocol::GetDownTarget6() const [member function]
    cls.add_method('GetDownTarget6', 
                   'ns3::IpL4Protocol::DownTargetCallback6', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## ip-l4-protocol.h (module 'internet'): int ns3::IpL4Protocol::GetProtocolNumber() const [member function]
    cls.add_method('GetProtocolNumber', 
                   'int', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## ip-l4-protocol.h (module 'internet'): static ns3::TypeId ns3::IpL4Protocol::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## ip-l4-protocol.h (module 'internet'): ns3::IpL4Protocol::RxStatus ns3::IpL4Protocol::Receive(ns3::Ptr<ns3::Packet> p, ns3::Ipv4Header const & header, ns3::Ptr<ns3::Ipv4Interface> incomingInterface) [member function]
    cls.add_method('Receive', 
                   'ns3::IpL4Protocol::RxStatus', 
                   [param('ns3::Ptr< ns3::Packet >', 'p'), param('ns3::Ipv4Header const &', 'header'), param('ns3::Ptr< ns3::Ipv4Interface >', 'incomingInterface')], 
                   is_pure_virtual=True, is_virtual=True)
    ## ip-l4-protocol.h (module 'internet'): ns3::IpL4Protocol::RxStatus ns3::IpL4Protocol::Receive(ns3::Ptr<ns3::Packet> p, ns3::Ipv6Header const & header, ns3::Ptr<ns3::Ipv6Interface> incomingInterface) [member function]
    cls.add_method('Receive', 
                   'ns3::IpL4Protocol::RxStatus', 
                   [param('ns3::Ptr< ns3::Packet >', 'p'), param('ns3::Ipv6Header const &', 'header'), param('ns3::Ptr< ns3::Ipv6Interface >', 'incomingInterface')], 
                   is_pure_virtual=True, is_virtual=True)
    ## ip-l4-protocol.h (module 'internet'): void ns3::IpL4Protocol::ReceiveIcmp(ns3::Ipv4Address icmpSource, uint8_t icmpTtl, uint8_t icmpType, uint8_t icmpCode, uint32_t icmpInfo, ns3::Ipv4Address payloadSource, ns3::Ipv4Address payloadDestination, uint8_t const * payload) [member function]
    cls.add_method('ReceiveIcmp', 
                   'void', 
                   [param('ns3::Ipv4Address', 'icmpSource'), param('uint8_t', 'icmpTtl'), param('uint8_t', 'icmpType'), param('uint8_t', 'icmpCode'), param('uint32_t', 'icmpInfo'), param('ns3::Ipv4Address', 'payloadSource'), param('ns3::Ipv4Address', 'payloadDestination'), param('uint8_t const *', 'payload')], 
                   is_virtual=True)
    ## ip-l4-protocol.h (module 'internet'): void ns3::IpL4Protocol::ReceiveIcmp(ns3::Ipv6Address icmpSource, uint8_t icmpTtl, uint8_t icmpType, uint8_t icmpCode, uint32_t icmpInfo, ns3::Ipv6Address payloadSource, ns3::Ipv6Address payloadDestination, uint8_t const * payload) [member function]
    cls.add_method('ReceiveIcmp', 
                   'void', 
                   [param('ns3::Ipv6Address', 'icmpSource'), param('uint8_t', 'icmpTtl'), param('uint8_t', 'icmpType'), param('uint8_t', 'icmpCode'), param('uint32_t', 'icmpInfo'), param('ns3::Ipv6Address', 'payloadSource'), param('ns3::Ipv6Address', 'payloadDestination'), param('uint8_t const *', 'payload')], 
                   is_virtual=True)
    ## ip-l4-protocol.h (module 'internet'): void ns3::IpL4Protocol::SetDownTarget(ns3::IpL4Protocol::DownTargetCallback cb) [member function]
    cls.add_method('SetDownTarget', 
                   'void', 
                   [param('ns3::Callback< void, ns3::Ptr< ns3::Packet >, ns3::Ipv4Address, ns3::Ipv4Address, unsigned char, ns3::Ptr< ns3::Ipv4Route >, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'cb')], 
                   is_pure_virtual=True, is_virtual=True)
    ## ip-l4-protocol.h (module 'internet'): void ns3::IpL4Protocol::SetDownTarget6(ns3::IpL4Protocol::DownTargetCallback6 cb) [member function]
    cls.add_method('SetDownTarget6', 
                   'void', 
                   [param('ns3::Callback< void, ns3::Ptr< ns3::Packet >, ns3::Ipv6Address, ns3::Ipv6Address, unsigned char, ns3::Ptr< ns3::Ipv6Route >, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'cb')], 
                   is_pure_virtual=True, is_virtual=True)
    return

def register_Ns3Ipv4_methods(root_module, cls):
    ## ipv4.h (module 'internet'): ns3::Ipv4::Ipv4(ns3::Ipv4 const & arg0) [constructor]
    cls.add_constructor([param('ns3::Ipv4 const &', 'arg0')])
    ## ipv4.h (module 'internet'): ns3::Ipv4::Ipv4() [constructor]
    cls.add_constructor([])
    ## ipv4.h (module 'internet'): bool ns3::Ipv4::AddAddress(uint32_t interface, ns3::Ipv4InterfaceAddress address) [member function]
    cls.add_method('AddAddress', 
                   'bool', 
                   [param('uint32_t', 'interface'), param('ns3::Ipv4InterfaceAddress', 'address')], 
                   is_pure_virtual=True, is_virtual=True)
    ## ipv4.h (module 'internet'): uint32_t ns3::Ipv4::AddInterface(ns3::Ptr<ns3::NetDevice> device) [member function]
    cls.add_method('AddInterface', 
                   'uint32_t', 
                   [param('ns3::Ptr< ns3::NetDevice >', 'device')], 
                   is_pure_virtual=True, is_virtual=True)
    ## ipv4.h (module 'internet'): ns3::Ptr<ns3::Socket> ns3::Ipv4::CreateRawSocket() [member function]
    cls.add_method('CreateRawSocket', 
                   'ns3::Ptr< ns3::Socket >', 
                   [], 
                   is_pure_virtual=True, is_virtual=True)
    ## ipv4.h (module 'internet'): void ns3::Ipv4::DeleteRawSocket(ns3::Ptr<ns3::Socket> socket) [member function]
    cls.add_method('DeleteRawSocket', 
                   'void', 
                   [param('ns3::Ptr< ns3::Socket >', 'socket')], 
                   is_pure_virtual=True, is_virtual=True)
    ## ipv4.h (module 'internet'): ns3::Ipv4InterfaceAddress ns3::Ipv4::GetAddress(uint32_t interface, uint32_t addressIndex) const [member function]
    cls.add_method('GetAddress', 
                   'ns3::Ipv4InterfaceAddress', 
                   [param('uint32_t', 'interface'), param('uint32_t', 'addressIndex')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## ipv4.h (module 'internet'): int32_t ns3::Ipv4::GetInterfaceForAddress(ns3::Ipv4Address address) const [member function]
    cls.add_method('GetInterfaceForAddress', 
                   'int32_t', 
                   [param('ns3::Ipv4Address', 'address')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## ipv4.h (module 'internet'): int32_t ns3::Ipv4::GetInterfaceForDevice(ns3::Ptr<const ns3::NetDevice> device) const [member function]
    cls.add_method('GetInterfaceForDevice', 
                   'int32_t', 
                   [param('ns3::Ptr< ns3::NetDevice const >', 'device')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## ipv4.h (module 'internet'): int32_t ns3::Ipv4::GetInterfaceForPrefix(ns3::Ipv4Address address, ns3::Ipv4Mask mask) const [member function]
    cls.add_method('GetInterfaceForPrefix', 
                   'int32_t', 
                   [param('ns3::Ipv4Address', 'address'), param('ns3::Ipv4Mask', 'mask')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## ipv4.h (module 'internet'): uint16_t ns3::Ipv4::GetMetric(uint32_t interface) const [member function]
    cls.add_method('GetMetric', 
                   'uint16_t', 
                   [param('uint32_t', 'interface')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## ipv4.h (module 'internet'): uint16_t ns3::Ipv4::GetMtu(uint32_t interface) const [member function]
    cls.add_method('GetMtu', 
                   'uint16_t', 
                   [param('uint32_t', 'interface')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## ipv4.h (module 'internet'): uint32_t ns3::Ipv4::GetNAddresses(uint32_t interface) const [member function]
    cls.add_method('GetNAddresses', 
                   'uint32_t', 
                   [param('uint32_t', 'interface')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## ipv4.h (module 'internet'): uint32_t ns3::Ipv4::GetNInterfaces() const [member function]
    cls.add_method('GetNInterfaces', 
                   'uint32_t', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## ipv4.h (module 'internet'): ns3::Ptr<ns3::NetDevice> ns3::Ipv4::GetNetDevice(uint32_t interface) [member function]
    cls.add_method('GetNetDevice', 
                   'ns3::Ptr< ns3::NetDevice >', 
                   [param('uint32_t', 'interface')], 
                   is_pure_virtual=True, is_virtual=True)
    ## ipv4.h (module 'internet'): ns3::Ptr<ns3::IpL4Protocol> ns3::Ipv4::GetProtocol(int protocolNumber) const [member function]
    cls.add_method('GetProtocol', 
                   'ns3::Ptr< ns3::IpL4Protocol >', 
                   [param('int', 'protocolNumber')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## ipv4.h (module 'internet'): ns3::Ptr<ns3::IpL4Protocol> ns3::Ipv4::GetProtocol(int protocolNumber, int32_t interfaceIndex) const [member function]
    cls.add_method('GetProtocol', 
                   'ns3::Ptr< ns3::IpL4Protocol >', 
                   [param('int', 'protocolNumber'), param('int32_t', 'interfaceIndex')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## ipv4.h (module 'internet'): ns3::Ptr<ns3::Ipv4RoutingProtocol> ns3::Ipv4::GetRoutingProtocol() const [member function]
    cls.add_method('GetRoutingProtocol', 
                   'ns3::Ptr< ns3::Ipv4RoutingProtocol >', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## ipv4.h (module 'internet'): static ns3::TypeId ns3::Ipv4::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## ipv4.h (module 'internet'): void ns3::Ipv4::Insert(ns3::Ptr<ns3::IpL4Protocol> protocol) [member function]
    cls.add_method('Insert', 
                   'void', 
                   [param('ns3::Ptr< ns3::IpL4Protocol >', 'protocol')], 
                   is_pure_virtual=True, is_virtual=True)
    ## ipv4.h (module 'internet'): void ns3::Ipv4::Insert(ns3::Ptr<ns3::IpL4Protocol> protocol, uint32_t interfaceIndex) [member function]
    cls.add_method('Insert', 
                   'void', 
                   [param('ns3::Ptr< ns3::IpL4Protocol >', 'protocol'), param('uint32_t', 'interfaceIndex')], 
                   is_pure_virtual=True, is_virtual=True)
    ## ipv4.h (module 'internet'): bool ns3::Ipv4::IsDestinationAddress(ns3::Ipv4Address address, uint32_t iif) const [member function]
    cls.add_method('IsDestinationAddress', 
                   'bool', 
                   [param('ns3::Ipv4Address', 'address'), param('uint32_t', 'iif')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## ipv4.h (module 'internet'): bool ns3::Ipv4::IsForwarding(uint32_t interface) const [member function]
    cls.add_method('IsForwarding', 
                   'bool', 
                   [param('uint32_t', 'interface')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## ipv4.h (module 'internet'): bool ns3::Ipv4::IsUp(uint32_t interface) const [member function]
    cls.add_method('IsUp', 
                   'bool', 
                   [param('uint32_t', 'interface')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## ipv4.h (module 'internet'): void ns3::Ipv4::Remove(ns3::Ptr<ns3::IpL4Protocol> protocol) [member function]
    cls.add_method('Remove', 
                   'void', 
                   [param('ns3::Ptr< ns3::IpL4Protocol >', 'protocol')], 
                   is_pure_virtual=True, is_virtual=True)
    ## ipv4.h (module 'internet'): void ns3::Ipv4::Remove(ns3::Ptr<ns3::IpL4Protocol> protocol, uint32_t interfaceIndex) [member function]
    cls.add_method('Remove', 
                   'void', 
                   [param('ns3::Ptr< ns3::IpL4Protocol >', 'protocol'), param('uint32_t', 'interfaceIndex')], 
                   is_pure_virtual=True, is_virtual=True)
    ## ipv4.h (module 'internet'): bool ns3::Ipv4::RemoveAddress(uint32_t interface, uint32_t addressIndex) [member function]
    cls.add_method('RemoveAddress', 
                   'bool', 
                   [param('uint32_t', 'interface'), param('uint32_t', 'addressIndex')], 
                   is_pure_virtual=True, is_virtual=True)
    ## ipv4.h (module 'internet'): bool ns3::Ipv4::RemoveAddress(uint32_t interface, ns3::Ipv4Address address) [member function]
    cls.add_method('RemoveAddress', 
                   'bool', 
                   [param('uint32_t', 'interface'), param('ns3::Ipv4Address', 'address')], 
                   is_pure_virtual=True, is_virtual=True)
    ## ipv4.h (module 'internet'): ns3::Ipv4Address ns3::Ipv4::SelectSourceAddress(ns3::Ptr<const ns3::NetDevice> device, ns3::Ipv4Address dst, ns3::Ipv4InterfaceAddress::InterfaceAddressScope_e scope) [member function]
    cls.add_method('SelectSourceAddress', 
                   'ns3::Ipv4Address', 
                   [param('ns3::Ptr< ns3::NetDevice const >', 'device'), param('ns3::Ipv4Address', 'dst'), param('ns3::Ipv4InterfaceAddress::InterfaceAddressScope_e', 'scope')], 
                   is_pure_virtual=True, is_virtual=True)
    ## ipv4.h (module 'internet'): void ns3::Ipv4::Send(ns3::Ptr<ns3::Packet> packet, ns3::Ipv4Address source, ns3::Ipv4Address destination, uint8_t protocol, ns3::Ptr<ns3::Ipv4Route> route) [member function]
    cls.add_method('Send', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('ns3::Ipv4Address', 'source'), param('ns3::Ipv4Address', 'destination'), param('uint8_t', 'protocol'), param('ns3::Ptr< ns3::Ipv4Route >', 'route')], 
                   is_pure_virtual=True, is_virtual=True)
    ## ipv4.h (module 'internet'): void ns3::Ipv4::SendWithHeader(ns3::Ptr<ns3::Packet> packet, ns3::Ipv4Header ipHeader, ns3::Ptr<ns3::Ipv4Route> route) [member function]
    cls.add_method('SendWithHeader', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('ns3::Ipv4Header', 'ipHeader'), param('ns3::Ptr< ns3::Ipv4Route >', 'route')], 
                   is_pure_virtual=True, is_virtual=True)
    ## ipv4.h (module 'internet'): void ns3::Ipv4::SetDown(uint32_t interface) [member function]
    cls.add_method('SetDown', 
                   'void', 
                   [param('uint32_t', 'interface')], 
                   is_pure_virtual=True, is_virtual=True)
    ## ipv4.h (module 'internet'): void ns3::Ipv4::SetForwarding(uint32_t interface, bool val) [member function]
    cls.add_method('SetForwarding', 
                   'void', 
                   [param('uint32_t', 'interface'), param('bool', 'val')], 
                   is_pure_virtual=True, is_virtual=True)
    ## ipv4.h (module 'internet'): void ns3::Ipv4::SetMetric(uint32_t interface, uint16_t metric) [member function]
    cls.add_method('SetMetric', 
                   'void', 
                   [param('uint32_t', 'interface'), param('uint16_t', 'metric')], 
                   is_pure_virtual=True, is_virtual=True)
    ## ipv4.h (module 'internet'): void ns3::Ipv4::SetRoutingProtocol(ns3::Ptr<ns3::Ipv4RoutingProtocol> routingProtocol) [member function]
    cls.add_method('SetRoutingProtocol', 
                   'void', 
                   [param('ns3::Ptr< ns3::Ipv4RoutingProtocol >', 'routingProtocol')], 
                   is_pure_virtual=True, is_virtual=True)
    ## ipv4.h (module 'internet'): void ns3::Ipv4::SetUp(uint32_t interface) [member function]
    cls.add_method('SetUp', 
                   'void', 
                   [param('uint32_t', 'interface')], 
                   is_pure_virtual=True, is_virtual=True)
    ## ipv4.h (module 'internet'): ns3::Ipv4Address ns3::Ipv4::SourceAddressSelection(uint32_t interface, ns3::Ipv4Address dest) [member function]
    cls.add_method('SourceAddressSelection', 
                   'ns3::Ipv4Address', 
                   [param('uint32_t', 'interface'), param('ns3::Ipv4Address', 'dest')], 
                   is_pure_virtual=True, is_virtual=True)
    ## ipv4.h (module 'internet'): ns3::Ipv4::IF_ANY [variable]
    cls.add_static_attribute('IF_ANY', 'uint32_t const', is_const=True)
    ## ipv4.h (module 'internet'): bool ns3::Ipv4::GetIpForward() const [member function]
    cls.add_method('GetIpForward', 
                   'bool', 
                   [], 
                   is_pure_virtual=True, is_const=True, visibility='private', is_virtual=True)
    ## ipv4.h (module 'internet'): bool ns3::Ipv4::GetWeakEsModel() const [member function]
    cls.add_method('GetWeakEsModel', 
                   'bool', 
                   [], 
                   is_pure_virtual=True, is_const=True, visibility='private', is_virtual=True)
    ## ipv4.h (module 'internet'): void ns3::Ipv4::SetIpForward(bool forward) [member function]
    cls.add_method('SetIpForward', 
                   'void', 
                   [param('bool', 'forward')], 
                   is_pure_virtual=True, visibility='private', is_virtual=True)
    ## ipv4.h (module 'internet'): void ns3::Ipv4::SetWeakEsModel(bool model) [member function]
    cls.add_method('SetWeakEsModel', 
                   'void', 
                   [param('bool', 'model')], 
                   is_pure_virtual=True, visibility='private', is_virtual=True)
    return

def register_Ns3Ipv4AddressChecker_methods(root_module, cls):
    ## ipv4-address.h (module 'network'): ns3::Ipv4AddressChecker::Ipv4AddressChecker() [constructor]
    cls.add_constructor([])
    ## ipv4-address.h (module 'network'): ns3::Ipv4AddressChecker::Ipv4AddressChecker(ns3::Ipv4AddressChecker const & arg0) [constructor]
    cls.add_constructor([param('ns3::Ipv4AddressChecker const &', 'arg0')])
    return

def register_Ns3Ipv4AddressValue_methods(root_module, cls):
    ## ipv4-address.h (module 'network'): ns3::Ipv4AddressValue::Ipv4AddressValue() [constructor]
    cls.add_constructor([])
    ## ipv4-address.h (module 'network'): ns3::Ipv4AddressValue::Ipv4AddressValue(ns3::Ipv4Address const & value) [constructor]
    cls.add_constructor([param('ns3::Ipv4Address const &', 'value')])
    ## ipv4-address.h (module 'network'): ns3::Ipv4AddressValue::Ipv4AddressValue(ns3::Ipv4AddressValue const & arg0) [constructor]
    cls.add_constructor([param('ns3::Ipv4AddressValue const &', 'arg0')])
    ## ipv4-address.h (module 'network'): ns3::Ptr<ns3::AttributeValue> ns3::Ipv4AddressValue::Copy() const [member function]
    cls.add_method('Copy', 
                   'ns3::Ptr< ns3::AttributeValue >', 
                   [], 
                   is_const=True, is_virtual=True)
    ## ipv4-address.h (module 'network'): bool ns3::Ipv4AddressValue::DeserializeFromString(std::string value, ns3::Ptr<const ns3::AttributeChecker> checker) [member function]
    cls.add_method('DeserializeFromString', 
                   'bool', 
                   [param('std::string', 'value'), param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_virtual=True)
    ## ipv4-address.h (module 'network'): ns3::Ipv4Address ns3::Ipv4AddressValue::Get() const [member function]
    cls.add_method('Get', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## ipv4-address.h (module 'network'): std::string ns3::Ipv4AddressValue::SerializeToString(ns3::Ptr<const ns3::AttributeChecker> checker) const [member function]
    cls.add_method('SerializeToString', 
                   'std::string', 
                   [param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_const=True, is_virtual=True)
    ## ipv4-address.h (module 'network'): void ns3::Ipv4AddressValue::Set(ns3::Ipv4Address const & value) [member function]
    cls.add_method('Set', 
                   'void', 
                   [param('ns3::Ipv4Address const &', 'value')])
    return

def register_Ns3Ipv4Interface_methods(root_module, cls):
    ## ipv4-interface.h (module 'internet'): static ns3::TypeId ns3::Ipv4Interface::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## ipv4-interface.h (module 'internet'): ns3::Ipv4Interface::Ipv4Interface() [constructor]
    cls.add_constructor([])
    ## ipv4-interface.h (module 'internet'): void ns3::Ipv4Interface::SetNode(ns3::Ptr<ns3::Node> node) [member function]
    cls.add_method('SetNode', 
                   'void', 
                   [param('ns3::Ptr< ns3::Node >', 'node')])
    ## ipv4-interface.h (module 'internet'): void ns3::Ipv4Interface::SetDevice(ns3::Ptr<ns3::NetDevice> device) [member function]
    cls.add_method('SetDevice', 
                   'void', 
                   [param('ns3::Ptr< ns3::NetDevice >', 'device')])
    ## ipv4-interface.h (module 'internet'): void ns3::Ipv4Interface::SetTrafficControl(ns3::Ptr<ns3::TrafficControlLayer> tc) [member function]
    cls.add_method('SetTrafficControl', 
                   'void', 
                   [param('ns3::Ptr< ns3::TrafficControlLayer >', 'tc')])
    ## ipv4-interface.h (module 'internet'): void ns3::Ipv4Interface::SetArpCache(ns3::Ptr<ns3::ArpCache> arpCache) [member function]
    cls.add_method('SetArpCache', 
                   'void', 
                   [param('ns3::Ptr< ns3::ArpCache >', 'arpCache')])
    ## ipv4-interface.h (module 'internet'): ns3::Ptr<ns3::NetDevice> ns3::Ipv4Interface::GetDevice() const [member function]
    cls.add_method('GetDevice', 
                   'ns3::Ptr< ns3::NetDevice >', 
                   [], 
                   is_const=True)
    ## ipv4-interface.h (module 'internet'): ns3::Ptr<ns3::ArpCache> ns3::Ipv4Interface::GetArpCache() const [member function]
    cls.add_method('GetArpCache', 
                   'ns3::Ptr< ns3::ArpCache >', 
                   [], 
                   is_const=True)
    ## ipv4-interface.h (module 'internet'): void ns3::Ipv4Interface::SetMetric(uint16_t metric) [member function]
    cls.add_method('SetMetric', 
                   'void', 
                   [param('uint16_t', 'metric')])
    ## ipv4-interface.h (module 'internet'): uint16_t ns3::Ipv4Interface::GetMetric() const [member function]
    cls.add_method('GetMetric', 
                   'uint16_t', 
                   [], 
                   is_const=True)
    ## ipv4-interface.h (module 'internet'): bool ns3::Ipv4Interface::IsUp() const [member function]
    cls.add_method('IsUp', 
                   'bool', 
                   [], 
                   is_const=True)
    ## ipv4-interface.h (module 'internet'): bool ns3::Ipv4Interface::IsDown() const [member function]
    cls.add_method('IsDown', 
                   'bool', 
                   [], 
                   is_const=True)
    ## ipv4-interface.h (module 'internet'): void ns3::Ipv4Interface::SetUp() [member function]
    cls.add_method('SetUp', 
                   'void', 
                   [])
    ## ipv4-interface.h (module 'internet'): void ns3::Ipv4Interface::SetDown() [member function]
    cls.add_method('SetDown', 
                   'void', 
                   [])
    ## ipv4-interface.h (module 'internet'): bool ns3::Ipv4Interface::IsForwarding() const [member function]
    cls.add_method('IsForwarding', 
                   'bool', 
                   [], 
                   is_const=True)
    ## ipv4-interface.h (module 'internet'): void ns3::Ipv4Interface::SetForwarding(bool val) [member function]
    cls.add_method('SetForwarding', 
                   'void', 
                   [param('bool', 'val')])
    ## ipv4-interface.h (module 'internet'): void ns3::Ipv4Interface::Send(ns3::Ptr<ns3::Packet> p, ns3::Ipv4Header const & hdr, ns3::Ipv4Address dest) [member function]
    cls.add_method('Send', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet >', 'p'), param('ns3::Ipv4Header const &', 'hdr'), param('ns3::Ipv4Address', 'dest')])
    ## ipv4-interface.h (module 'internet'): bool ns3::Ipv4Interface::AddAddress(ns3::Ipv4InterfaceAddress address) [member function]
    cls.add_method('AddAddress', 
                   'bool', 
                   [param('ns3::Ipv4InterfaceAddress', 'address')])
    ## ipv4-interface.h (module 'internet'): ns3::Ipv4InterfaceAddress ns3::Ipv4Interface::GetAddress(uint32_t index) const [member function]
    cls.add_method('GetAddress', 
                   'ns3::Ipv4InterfaceAddress', 
                   [param('uint32_t', 'index')], 
                   is_const=True)
    ## ipv4-interface.h (module 'internet'): uint32_t ns3::Ipv4Interface::GetNAddresses() const [member function]
    cls.add_method('GetNAddresses', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## ipv4-interface.h (module 'internet'): ns3::Ipv4InterfaceAddress ns3::Ipv4Interface::RemoveAddress(uint32_t index) [member function]
    cls.add_method('RemoveAddress', 
                   'ns3::Ipv4InterfaceAddress', 
                   [param('uint32_t', 'index')])
    ## ipv4-interface.h (module 'internet'): ns3::Ipv4InterfaceAddress ns3::Ipv4Interface::RemoveAddress(ns3::Ipv4Address address) [member function]
    cls.add_method('RemoveAddress', 
                   'ns3::Ipv4InterfaceAddress', 
                   [param('ns3::Ipv4Address', 'address')])
    ## ipv4-interface.h (module 'internet'): void ns3::Ipv4Interface::DoDispose() [member function]
    cls.add_method('DoDispose', 
                   'void', 
                   [], 
                   visibility='protected', is_virtual=True)
    return

def register_Ns3Ipv4L3Protocol_methods(root_module, cls):
    ## ipv4-l3-protocol.h (module 'internet'): ns3::Ipv4L3Protocol::Ipv4L3Protocol() [constructor]
    cls.add_constructor([])
    ## ipv4-l3-protocol.h (module 'internet'): bool ns3::Ipv4L3Protocol::AddAddress(uint32_t i, ns3::Ipv4InterfaceAddress address) [member function]
    cls.add_method('AddAddress', 
                   'bool', 
                   [param('uint32_t', 'i'), param('ns3::Ipv4InterfaceAddress', 'address')], 
                   is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): uint32_t ns3::Ipv4L3Protocol::AddInterface(ns3::Ptr<ns3::NetDevice> device) [member function]
    cls.add_method('AddInterface', 
                   'uint32_t', 
                   [param('ns3::Ptr< ns3::NetDevice >', 'device')], 
                   is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): ns3::Ptr<ns3::Socket> ns3::Ipv4L3Protocol::CreateRawSocket() [member function]
    cls.add_method('CreateRawSocket', 
                   'ns3::Ptr< ns3::Socket >', 
                   [], 
                   is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): void ns3::Ipv4L3Protocol::DeleteRawSocket(ns3::Ptr<ns3::Socket> socket) [member function]
    cls.add_method('DeleteRawSocket', 
                   'void', 
                   [param('ns3::Ptr< ns3::Socket >', 'socket')], 
                   is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): ns3::Ipv4InterfaceAddress ns3::Ipv4L3Protocol::GetAddress(uint32_t interfaceIndex, uint32_t addressIndex) const [member function]
    cls.add_method('GetAddress', 
                   'ns3::Ipv4InterfaceAddress', 
                   [param('uint32_t', 'interfaceIndex'), param('uint32_t', 'addressIndex')], 
                   is_const=True, is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): ns3::Ptr<ns3::Ipv4Interface> ns3::Ipv4L3Protocol::GetInterface(uint32_t i) const [member function]
    cls.add_method('GetInterface', 
                   'ns3::Ptr< ns3::Ipv4Interface >', 
                   [param('uint32_t', 'i')], 
                   is_const=True)
    ## ipv4-l3-protocol.h (module 'internet'): int32_t ns3::Ipv4L3Protocol::GetInterfaceForAddress(ns3::Ipv4Address addr) const [member function]
    cls.add_method('GetInterfaceForAddress', 
                   'int32_t', 
                   [param('ns3::Ipv4Address', 'addr')], 
                   is_const=True, is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): int32_t ns3::Ipv4L3Protocol::GetInterfaceForDevice(ns3::Ptr<const ns3::NetDevice> device) const [member function]
    cls.add_method('GetInterfaceForDevice', 
                   'int32_t', 
                   [param('ns3::Ptr< ns3::NetDevice const >', 'device')], 
                   is_const=True, is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): int32_t ns3::Ipv4L3Protocol::GetInterfaceForPrefix(ns3::Ipv4Address addr, ns3::Ipv4Mask mask) const [member function]
    cls.add_method('GetInterfaceForPrefix', 
                   'int32_t', 
                   [param('ns3::Ipv4Address', 'addr'), param('ns3::Ipv4Mask', 'mask')], 
                   is_const=True, is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): uint16_t ns3::Ipv4L3Protocol::GetMetric(uint32_t i) const [member function]
    cls.add_method('GetMetric', 
                   'uint16_t', 
                   [param('uint32_t', 'i')], 
                   is_const=True, is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): uint16_t ns3::Ipv4L3Protocol::GetMtu(uint32_t i) const [member function]
    cls.add_method('GetMtu', 
                   'uint16_t', 
                   [param('uint32_t', 'i')], 
                   is_const=True, is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): uint32_t ns3::Ipv4L3Protocol::GetNAddresses(uint32_t interface) const [member function]
    cls.add_method('GetNAddresses', 
                   'uint32_t', 
                   [param('uint32_t', 'interface')], 
                   is_const=True, is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): uint32_t ns3::Ipv4L3Protocol::GetNInterfaces() const [member function]
    cls.add_method('GetNInterfaces', 
                   'uint32_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): ns3::Ptr<ns3::NetDevice> ns3::Ipv4L3Protocol::GetNetDevice(uint32_t i) [member function]
    cls.add_method('GetNetDevice', 
                   'ns3::Ptr< ns3::NetDevice >', 
                   [param('uint32_t', 'i')], 
                   is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): ns3::Ptr<ns3::IpL4Protocol> ns3::Ipv4L3Protocol::GetProtocol(int protocolNumber) const [member function]
    cls.add_method('GetProtocol', 
                   'ns3::Ptr< ns3::IpL4Protocol >', 
                   [param('int', 'protocolNumber')], 
                   is_const=True, is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): ns3::Ptr<ns3::IpL4Protocol> ns3::Ipv4L3Protocol::GetProtocol(int protocolNumber, int32_t interfaceIndex) const [member function]
    cls.add_method('GetProtocol', 
                   'ns3::Ptr< ns3::IpL4Protocol >', 
                   [param('int', 'protocolNumber'), param('int32_t', 'interfaceIndex')], 
                   is_const=True, is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): ns3::Ptr<ns3::Ipv4RoutingProtocol> ns3::Ipv4L3Protocol::GetRoutingProtocol() const [member function]
    cls.add_method('GetRoutingProtocol', 
                   'ns3::Ptr< ns3::Ipv4RoutingProtocol >', 
                   [], 
                   is_const=True, is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): static ns3::TypeId ns3::Ipv4L3Protocol::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## ipv4-l3-protocol.h (module 'internet'): void ns3::Ipv4L3Protocol::Insert(ns3::Ptr<ns3::IpL4Protocol> protocol) [member function]
    cls.add_method('Insert', 
                   'void', 
                   [param('ns3::Ptr< ns3::IpL4Protocol >', 'protocol')], 
                   is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): void ns3::Ipv4L3Protocol::Insert(ns3::Ptr<ns3::IpL4Protocol> protocol, uint32_t interfaceIndex) [member function]
    cls.add_method('Insert', 
                   'void', 
                   [param('ns3::Ptr< ns3::IpL4Protocol >', 'protocol'), param('uint32_t', 'interfaceIndex')], 
                   is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): bool ns3::Ipv4L3Protocol::IsDestinationAddress(ns3::Ipv4Address address, uint32_t iif) const [member function]
    cls.add_method('IsDestinationAddress', 
                   'bool', 
                   [param('ns3::Ipv4Address', 'address'), param('uint32_t', 'iif')], 
                   is_const=True, is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): bool ns3::Ipv4L3Protocol::IsForwarding(uint32_t i) const [member function]
    cls.add_method('IsForwarding', 
                   'bool', 
                   [param('uint32_t', 'i')], 
                   is_const=True, is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): bool ns3::Ipv4L3Protocol::IsUnicast(ns3::Ipv4Address ad) const [member function]
    cls.add_method('IsUnicast', 
                   'bool', 
                   [param('ns3::Ipv4Address', 'ad')], 
                   is_const=True)
    ## ipv4-l3-protocol.h (module 'internet'): bool ns3::Ipv4L3Protocol::IsUp(uint32_t i) const [member function]
    cls.add_method('IsUp', 
                   'bool', 
                   [param('uint32_t', 'i')], 
                   is_const=True, is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): void ns3::Ipv4L3Protocol::Receive(ns3::Ptr<ns3::NetDevice> device, ns3::Ptr<const ns3::Packet> p, uint16_t protocol, ns3::Address const & from, ns3::Address const & to, ns3::NetDevice::PacketType packetType) [member function]
    cls.add_method('Receive', 
                   'void', 
                   [param('ns3::Ptr< ns3::NetDevice >', 'device'), param('ns3::Ptr< ns3::Packet const >', 'p'), param('uint16_t', 'protocol'), param('ns3::Address const &', 'from'), param('ns3::Address const &', 'to'), param('ns3::NetDevice::PacketType', 'packetType')])
    ## ipv4-l3-protocol.h (module 'internet'): void ns3::Ipv4L3Protocol::Remove(ns3::Ptr<ns3::IpL4Protocol> protocol) [member function]
    cls.add_method('Remove', 
                   'void', 
                   [param('ns3::Ptr< ns3::IpL4Protocol >', 'protocol')], 
                   is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): void ns3::Ipv4L3Protocol::Remove(ns3::Ptr<ns3::IpL4Protocol> protocol, uint32_t interfaceIndex) [member function]
    cls.add_method('Remove', 
                   'void', 
                   [param('ns3::Ptr< ns3::IpL4Protocol >', 'protocol'), param('uint32_t', 'interfaceIndex')], 
                   is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): bool ns3::Ipv4L3Protocol::RemoveAddress(uint32_t interfaceIndex, uint32_t addressIndex) [member function]
    cls.add_method('RemoveAddress', 
                   'bool', 
                   [param('uint32_t', 'interfaceIndex'), param('uint32_t', 'addressIndex')], 
                   is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): bool ns3::Ipv4L3Protocol::RemoveAddress(uint32_t interface, ns3::Ipv4Address address) [member function]
    cls.add_method('RemoveAddress', 
                   'bool', 
                   [param('uint32_t', 'interface'), param('ns3::Ipv4Address', 'address')], 
                   is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): ns3::Ipv4Address ns3::Ipv4L3Protocol::SelectSourceAddress(ns3::Ptr<const ns3::NetDevice> device, ns3::Ipv4Address dst, ns3::Ipv4InterfaceAddress::InterfaceAddressScope_e scope) [member function]
    cls.add_method('SelectSourceAddress', 
                   'ns3::Ipv4Address', 
                   [param('ns3::Ptr< ns3::NetDevice const >', 'device'), param('ns3::Ipv4Address', 'dst'), param('ns3::Ipv4InterfaceAddress::InterfaceAddressScope_e', 'scope')], 
                   is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): void ns3::Ipv4L3Protocol::Send(ns3::Ptr<ns3::Packet> packet, ns3::Ipv4Address source, ns3::Ipv4Address destination, uint8_t protocol, ns3::Ptr<ns3::Ipv4Route> route) [member function]
    cls.add_method('Send', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('ns3::Ipv4Address', 'source'), param('ns3::Ipv4Address', 'destination'), param('uint8_t', 'protocol'), param('ns3::Ptr< ns3::Ipv4Route >', 'route')], 
                   is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): void ns3::Ipv4L3Protocol::SendWithHeader(ns3::Ptr<ns3::Packet> packet, ns3::Ipv4Header ipHeader, ns3::Ptr<ns3::Ipv4Route> route) [member function]
    cls.add_method('SendWithHeader', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('ns3::Ipv4Header', 'ipHeader'), param('ns3::Ptr< ns3::Ipv4Route >', 'route')], 
                   is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): void ns3::Ipv4L3Protocol::SetDefaultTtl(uint8_t ttl) [member function]
    cls.add_method('SetDefaultTtl', 
                   'void', 
                   [param('uint8_t', 'ttl')])
    ## ipv4-l3-protocol.h (module 'internet'): void ns3::Ipv4L3Protocol::SetDown(uint32_t i) [member function]
    cls.add_method('SetDown', 
                   'void', 
                   [param('uint32_t', 'i')], 
                   is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): void ns3::Ipv4L3Protocol::SetForwarding(uint32_t i, bool val) [member function]
    cls.add_method('SetForwarding', 
                   'void', 
                   [param('uint32_t', 'i'), param('bool', 'val')], 
                   is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): void ns3::Ipv4L3Protocol::SetMetric(uint32_t i, uint16_t metric) [member function]
    cls.add_method('SetMetric', 
                   'void', 
                   [param('uint32_t', 'i'), param('uint16_t', 'metric')], 
                   is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): void ns3::Ipv4L3Protocol::SetNode(ns3::Ptr<ns3::Node> node) [member function]
    cls.add_method('SetNode', 
                   'void', 
                   [param('ns3::Ptr< ns3::Node >', 'node')])
    ## ipv4-l3-protocol.h (module 'internet'): void ns3::Ipv4L3Protocol::SetRoutingProtocol(ns3::Ptr<ns3::Ipv4RoutingProtocol> routingProtocol) [member function]
    cls.add_method('SetRoutingProtocol', 
                   'void', 
                   [param('ns3::Ptr< ns3::Ipv4RoutingProtocol >', 'routingProtocol')], 
                   is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): void ns3::Ipv4L3Protocol::SetUp(uint32_t i) [member function]
    cls.add_method('SetUp', 
                   'void', 
                   [param('uint32_t', 'i')], 
                   is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): ns3::Ipv4Address ns3::Ipv4L3Protocol::SourceAddressSelection(uint32_t interface, ns3::Ipv4Address dest) [member function]
    cls.add_method('SourceAddressSelection', 
                   'ns3::Ipv4Address', 
                   [param('uint32_t', 'interface'), param('ns3::Ipv4Address', 'dest')], 
                   is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): ns3::Ipv4L3Protocol::PROT_NUMBER [variable]
    cls.add_static_attribute('PROT_NUMBER', 'uint16_t const', is_const=True)
    ## ipv4-l3-protocol.h (module 'internet'): void ns3::Ipv4L3Protocol::DoDispose() [member function]
    cls.add_method('DoDispose', 
                   'void', 
                   [], 
                   visibility='protected', is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): void ns3::Ipv4L3Protocol::NotifyNewAggregate() [member function]
    cls.add_method('NotifyNewAggregate', 
                   'void', 
                   [], 
                   visibility='protected', is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): bool ns3::Ipv4L3Protocol::GetIpForward() const [member function]
    cls.add_method('GetIpForward', 
                   'bool', 
                   [], 
                   is_const=True, visibility='private', is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): bool ns3::Ipv4L3Protocol::GetWeakEsModel() const [member function]
    cls.add_method('GetWeakEsModel', 
                   'bool', 
                   [], 
                   is_const=True, visibility='private', is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): void ns3::Ipv4L3Protocol::SetIpForward(bool forward) [member function]
    cls.add_method('SetIpForward', 
                   'void', 
                   [param('bool', 'forward')], 
                   visibility='private', is_virtual=True)
    ## ipv4-l3-protocol.h (module 'internet'): void ns3::Ipv4L3Protocol::SetWeakEsModel(bool model) [member function]
    cls.add_method('SetWeakEsModel', 
                   'void', 
                   [param('bool', 'model')], 
                   visibility='private', is_virtual=True)
    return

def register_Ns3Ipv4MaskChecker_methods(root_module, cls):
    ## ipv4-address.h (module 'network'): ns3::Ipv4MaskChecker::Ipv4MaskChecker() [constructor]
    cls.add_constructor([])
    ## ipv4-address.h (module 'network'): ns3::Ipv4MaskChecker::Ipv4MaskChecker(ns3::Ipv4MaskChecker const & arg0) [constructor]
    cls.add_constructor([param('ns3::Ipv4MaskChecker const &', 'arg0')])
    return

def register_Ns3Ipv4MaskValue_methods(root_module, cls):
    ## ipv4-address.h (module 'network'): ns3::Ipv4MaskValue::Ipv4MaskValue() [constructor]
    cls.add_constructor([])
    ## ipv4-address.h (module 'network'): ns3::Ipv4MaskValue::Ipv4MaskValue(ns3::Ipv4Mask const & value) [constructor]
    cls.add_constructor([param('ns3::Ipv4Mask const &', 'value')])
    ## ipv4-address.h (module 'network'): ns3::Ipv4MaskValue::Ipv4MaskValue(ns3::Ipv4MaskValue const & arg0) [constructor]
    cls.add_constructor([param('ns3::Ipv4MaskValue const &', 'arg0')])
    ## ipv4-address.h (module 'network'): ns3::Ptr<ns3::AttributeValue> ns3::Ipv4MaskValue::Copy() const [member function]
    cls.add_method('Copy', 
                   'ns3::Ptr< ns3::AttributeValue >', 
                   [], 
                   is_const=True, is_virtual=True)
    ## ipv4-address.h (module 'network'): bool ns3::Ipv4MaskValue::DeserializeFromString(std::string value, ns3::Ptr<const ns3::AttributeChecker> checker) [member function]
    cls.add_method('DeserializeFromString', 
                   'bool', 
                   [param('std::string', 'value'), param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_virtual=True)
    ## ipv4-address.h (module 'network'): ns3::Ipv4Mask ns3::Ipv4MaskValue::Get() const [member function]
    cls.add_method('Get', 
                   'ns3::Ipv4Mask', 
                   [], 
                   is_const=True)
    ## ipv4-address.h (module 'network'): std::string ns3::Ipv4MaskValue::SerializeToString(ns3::Ptr<const ns3::AttributeChecker> checker) const [member function]
    cls.add_method('SerializeToString', 
                   'std::string', 
                   [param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_const=True, is_virtual=True)
    ## ipv4-address.h (module 'network'): void ns3::Ipv4MaskValue::Set(ns3::Ipv4Mask const & value) [member function]
    cls.add_method('Set', 
                   'void', 
                   [param('ns3::Ipv4Mask const &', 'value')])
    return

def register_Ns3Ipv4MulticastRoute_methods(root_module, cls):
    ## ipv4-route.h (module 'internet'): ns3::Ipv4MulticastRoute::Ipv4MulticastRoute(ns3::Ipv4MulticastRoute const & arg0) [constructor]
    cls.add_constructor([param('ns3::Ipv4MulticastRoute const &', 'arg0')])
    ## ipv4-route.h (module 'internet'): ns3::Ipv4MulticastRoute::Ipv4MulticastRoute() [constructor]
    cls.add_constructor([])
    ## ipv4-route.h (module 'internet'): ns3::Ipv4Address ns3::Ipv4MulticastRoute::GetGroup() const [member function]
    cls.add_method('GetGroup', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## ipv4-route.h (module 'internet'): ns3::Ipv4Address ns3::Ipv4MulticastRoute::GetOrigin() const [member function]
    cls.add_method('GetOrigin', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## ipv4-route.h (module 'internet'): std::map<unsigned int, unsigned int, std::less<unsigned int>, std::allocator<std::pair<const unsigned int, unsigned int> > > ns3::Ipv4MulticastRoute::GetOutputTtlMap() const [member function]
    cls.add_method('GetOutputTtlMap', 
                   'std::map< unsigned int, unsigned int >', 
                   [], 
                   is_const=True)
    ## ipv4-route.h (module 'internet'): uint32_t ns3::Ipv4MulticastRoute::GetParent() const [member function]
    cls.add_method('GetParent', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## ipv4-route.h (module 'internet'): void ns3::Ipv4MulticastRoute::SetGroup(ns3::Ipv4Address const group) [member function]
    cls.add_method('SetGroup', 
                   'void', 
                   [param('ns3::Ipv4Address const', 'group')])
    ## ipv4-route.h (module 'internet'): void ns3::Ipv4MulticastRoute::SetOrigin(ns3::Ipv4Address const origin) [member function]
    cls.add_method('SetOrigin', 
                   'void', 
                   [param('ns3::Ipv4Address const', 'origin')])
    ## ipv4-route.h (module 'internet'): void ns3::Ipv4MulticastRoute::SetOutputTtl(uint32_t oif, uint32_t ttl) [member function]
    cls.add_method('SetOutputTtl', 
                   'void', 
                   [param('uint32_t', 'oif'), param('uint32_t', 'ttl')])
    ## ipv4-route.h (module 'internet'): void ns3::Ipv4MulticastRoute::SetParent(uint32_t iif) [member function]
    cls.add_method('SetParent', 
                   'void', 
                   [param('uint32_t', 'iif')])
    ## ipv4-route.h (module 'internet'): ns3::Ipv4MulticastRoute::MAX_INTERFACES [variable]
    cls.add_static_attribute('MAX_INTERFACES', 'uint32_t const', is_const=True)
    ## ipv4-route.h (module 'internet'): ns3::Ipv4MulticastRoute::MAX_TTL [variable]
    cls.add_static_attribute('MAX_TTL', 'uint32_t const', is_const=True)
    return

def register_Ns3Ipv4Route_methods(root_module, cls):
    cls.add_output_stream_operator()
    ## ipv4-route.h (module 'internet'): ns3::Ipv4Route::Ipv4Route(ns3::Ipv4Route const & arg0) [constructor]
    cls.add_constructor([param('ns3::Ipv4Route const &', 'arg0')])
    ## ipv4-route.h (module 'internet'): ns3::Ipv4Route::Ipv4Route() [constructor]
    cls.add_constructor([])
    ## ipv4-route.h (module 'internet'): ns3::Ipv4Address ns3::Ipv4Route::GetDestination() const [member function]
    cls.add_method('GetDestination', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## ipv4-route.h (module 'internet'): ns3::Ipv4Address ns3::Ipv4Route::GetGateway() const [member function]
    cls.add_method('GetGateway', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## ipv4-route.h (module 'internet'): ns3::Ptr<ns3::NetDevice> ns3::Ipv4Route::GetOutputDevice() const [member function]
    cls.add_method('GetOutputDevice', 
                   'ns3::Ptr< ns3::NetDevice >', 
                   [], 
                   is_const=True)
    ## ipv4-route.h (module 'internet'): ns3::Ipv4Address ns3::Ipv4Route::GetSource() const [member function]
    cls.add_method('GetSource', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## ipv4-route.h (module 'internet'): void ns3::Ipv4Route::SetDestination(ns3::Ipv4Address dest) [member function]
    cls.add_method('SetDestination', 
                   'void', 
                   [param('ns3::Ipv4Address', 'dest')])
    ## ipv4-route.h (module 'internet'): void ns3::Ipv4Route::SetGateway(ns3::Ipv4Address gw) [member function]
    cls.add_method('SetGateway', 
                   'void', 
                   [param('ns3::Ipv4Address', 'gw')])
    ## ipv4-route.h (module 'internet'): void ns3::Ipv4Route::SetOutputDevice(ns3::Ptr<ns3::NetDevice> outputDevice) [member function]
    cls.add_method('SetOutputDevice', 
                   'void', 
                   [param('ns3::Ptr< ns3::NetDevice >', 'outputDevice')])
    ## ipv4-route.h (module 'internet'): void ns3::Ipv4Route::SetSource(ns3::Ipv4Address src) [member function]
    cls.add_method('SetSource', 
                   'void', 
                   [param('ns3::Ipv4Address', 'src')])
    return

def register_Ns3Ipv4RoutingProtocol_methods(root_module, cls):
    ## ipv4-routing-protocol.h (module 'internet'): ns3::Ipv4RoutingProtocol::Ipv4RoutingProtocol() [constructor]
    cls.add_constructor([])
    ## ipv4-routing-protocol.h (module 'internet'): ns3::Ipv4RoutingProtocol::Ipv4RoutingProtocol(ns3::Ipv4RoutingProtocol const & arg0) [constructor]
    cls.add_constructor([param('ns3::Ipv4RoutingProtocol const &', 'arg0')])
    ## ipv4-routing-protocol.h (module 'internet'): static ns3::TypeId ns3::Ipv4RoutingProtocol::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## ipv4-routing-protocol.h (module 'internet'): void ns3::Ipv4RoutingProtocol::NotifyAddAddress(uint32_t interface, ns3::Ipv4InterfaceAddress address) [member function]
    cls.add_method('NotifyAddAddress', 
                   'void', 
                   [param('uint32_t', 'interface'), param('ns3::Ipv4InterfaceAddress', 'address')], 
                   is_pure_virtual=True, is_virtual=True)
    ## ipv4-routing-protocol.h (module 'internet'): void ns3::Ipv4RoutingProtocol::NotifyInterfaceDown(uint32_t interface) [member function]
    cls.add_method('NotifyInterfaceDown', 
                   'void', 
                   [param('uint32_t', 'interface')], 
                   is_pure_virtual=True, is_virtual=True)
    ## ipv4-routing-protocol.h (module 'internet'): void ns3::Ipv4RoutingProtocol::NotifyInterfaceUp(uint32_t interface) [member function]
    cls.add_method('NotifyInterfaceUp', 
                   'void', 
                   [param('uint32_t', 'interface')], 
                   is_pure_virtual=True, is_virtual=True)
    ## ipv4-routing-protocol.h (module 'internet'): void ns3::Ipv4RoutingProtocol::NotifyRemoveAddress(uint32_t interface, ns3::Ipv4InterfaceAddress address) [member function]
    cls.add_method('NotifyRemoveAddress', 
                   'void', 
                   [param('uint32_t', 'interface'), param('ns3::Ipv4InterfaceAddress', 'address')], 
                   is_pure_virtual=True, is_virtual=True)
    ## ipv4-routing-protocol.h (module 'internet'): void ns3::Ipv4RoutingProtocol::PrintRoutingTable(ns3::Ptr<ns3::OutputStreamWrapper> stream, ns3::Time::Unit unit=::ns3::Time::Unit::S) const [member function]
    cls.add_method('PrintRoutingTable', 
                   'void', 
                   [param('ns3::Ptr< ns3::OutputStreamWrapper >', 'stream'), param('ns3::Time::Unit', 'unit', default_value='::ns3::Time::Unit::S')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## ipv4-routing-protocol.h (module 'internet'): bool ns3::Ipv4RoutingProtocol::RouteInput(ns3::Ptr<const ns3::Packet> p, ns3::Ipv4Header const & header, ns3::Ptr<const ns3::NetDevice> idev, ns3::Ipv4RoutingProtocol::UnicastForwardCallback ucb, ns3::Ipv4RoutingProtocol::MulticastForwardCallback mcb, ns3::Ipv4RoutingProtocol::LocalDeliverCallback lcb, ns3::Ipv4RoutingProtocol::ErrorCallback ecb) [member function]
    cls.add_method('RouteInput', 
                   'bool', 
                   [param('ns3::Ptr< ns3::Packet const >', 'p'), param('ns3::Ipv4Header const &', 'header'), param('ns3::Ptr< ns3::NetDevice const >', 'idev'), param('ns3::Callback< void, ns3::Ptr< ns3::Ipv4Route >, ns3::Ptr< ns3::Packet const >, ns3::Ipv4Header const &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'ucb'), param('ns3::Callback< void, ns3::Ptr< ns3::Ipv4MulticastRoute >, ns3::Ptr< ns3::Packet const >, ns3::Ipv4Header const &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'mcb'), param('ns3::Callback< void, ns3::Ptr< ns3::Packet const >, ns3::Ipv4Header const &, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'lcb'), param('ns3::Callback< void, ns3::Ptr< ns3::Packet const >, ns3::Ipv4Header const &, ns3::Socket::SocketErrno, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'ecb')], 
                   is_pure_virtual=True, is_virtual=True)
    ## ipv4-routing-protocol.h (module 'internet'): ns3::Ptr<ns3::Ipv4Route> ns3::Ipv4RoutingProtocol::RouteOutput(ns3::Ptr<ns3::Packet> p, ns3::Ipv4Header const & header, ns3::Ptr<ns3::NetDevice> oif, ns3::Socket::SocketErrno & sockerr) [member function]
    cls.add_method('RouteOutput', 
                   'ns3::Ptr< ns3::Ipv4Route >', 
                   [param('ns3::Ptr< ns3::Packet >', 'p'), param('ns3::Ipv4Header const &', 'header'), param('ns3::Ptr< ns3::NetDevice >', 'oif'), param('ns3::Socket::SocketErrno &', 'sockerr')], 
                   is_pure_virtual=True, is_virtual=True)
    ## ipv4-routing-protocol.h (module 'internet'): void ns3::Ipv4RoutingProtocol::SetIpv4(ns3::Ptr<ns3::Ipv4> ipv4) [member function]
    cls.add_method('SetIpv4', 
                   'void', 
                   [param('ns3::Ptr< ns3::Ipv4 >', 'ipv4')], 
                   is_pure_virtual=True, is_virtual=True)
    return

def register_Ns3Ipv6AddressChecker_methods(root_module, cls):
    ## ipv6-address.h (module 'network'): ns3::Ipv6AddressChecker::Ipv6AddressChecker() [constructor]
    cls.add_constructor([])
    ## ipv6-address.h (module 'network'): ns3::Ipv6AddressChecker::Ipv6AddressChecker(ns3::Ipv6AddressChecker const & arg0) [constructor]
    cls.add_constructor([param('ns3::Ipv6AddressChecker const &', 'arg0')])
    return

def register_Ns3Ipv6AddressValue_methods(root_module, cls):
    ## ipv6-address.h (module 'network'): ns3::Ipv6AddressValue::Ipv6AddressValue() [constructor]
    cls.add_constructor([])
    ## ipv6-address.h (module 'network'): ns3::Ipv6AddressValue::Ipv6AddressValue(ns3::Ipv6Address const & value) [constructor]
    cls.add_constructor([param('ns3::Ipv6Address const &', 'value')])
    ## ipv6-address.h (module 'network'): ns3::Ipv6AddressValue::Ipv6AddressValue(ns3::Ipv6AddressValue const & arg0) [constructor]
    cls.add_constructor([param('ns3::Ipv6AddressValue const &', 'arg0')])
    ## ipv6-address.h (module 'network'): ns3::Ptr<ns3::AttributeValue> ns3::Ipv6AddressValue::Copy() const [member function]
    cls.add_method('Copy', 
                   'ns3::Ptr< ns3::AttributeValue >', 
                   [], 
                   is_const=True, is_virtual=True)
    ## ipv6-address.h (module 'network'): bool ns3::Ipv6AddressValue::DeserializeFromString(std::string value, ns3::Ptr<const ns3::AttributeChecker> checker) [member function]
    cls.add_method('DeserializeFromString', 
                   'bool', 
                   [param('std::string', 'value'), param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_virtual=True)
    ## ipv6-address.h (module 'network'): ns3::Ipv6Address ns3::Ipv6AddressValue::Get() const [member function]
    cls.add_method('Get', 
                   'ns3::Ipv6Address', 
                   [], 
                   is_const=True)
    ## ipv6-address.h (module 'network'): std::string ns3::Ipv6AddressValue::SerializeToString(ns3::Ptr<const ns3::AttributeChecker> checker) const [member function]
    cls.add_method('SerializeToString', 
                   'std::string', 
                   [param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_const=True, is_virtual=True)
    ## ipv6-address.h (module 'network'): void ns3::Ipv6AddressValue::Set(ns3::Ipv6Address const & value) [member function]
    cls.add_method('Set', 
                   'void', 
                   [param('ns3::Ipv6Address const &', 'value')])
    return

def register_Ns3Ipv6PrefixChecker_methods(root_module, cls):
    ## ipv6-address.h (module 'network'): ns3::Ipv6PrefixChecker::Ipv6PrefixChecker() [constructor]
    cls.add_constructor([])
    ## ipv6-address.h (module 'network'): ns3::Ipv6PrefixChecker::Ipv6PrefixChecker(ns3::Ipv6PrefixChecker const & arg0) [constructor]
    cls.add_constructor([param('ns3::Ipv6PrefixChecker const &', 'arg0')])
    return

def register_Ns3Ipv6PrefixValue_methods(root_module, cls):
    ## ipv6-address.h (module 'network'): ns3::Ipv6PrefixValue::Ipv6PrefixValue() [constructor]
    cls.add_constructor([])
    ## ipv6-address.h (module 'network'): ns3::Ipv6PrefixValue::Ipv6PrefixValue(ns3::Ipv6Prefix const & value) [constructor]
    cls.add_constructor([param('ns3::Ipv6Prefix const &', 'value')])
    ## ipv6-address.h (module 'network'): ns3::Ipv6PrefixValue::Ipv6PrefixValue(ns3::Ipv6PrefixValue const & arg0) [constructor]
    cls.add_constructor([param('ns3::Ipv6PrefixValue const &', 'arg0')])
    ## ipv6-address.h (module 'network'): ns3::Ptr<ns3::AttributeValue> ns3::Ipv6PrefixValue::Copy() const [member function]
    cls.add_method('Copy', 
                   'ns3::Ptr< ns3::AttributeValue >', 
                   [], 
                   is_const=True, is_virtual=True)
    ## ipv6-address.h (module 'network'): bool ns3::Ipv6PrefixValue::DeserializeFromString(std::string value, ns3::Ptr<const ns3::AttributeChecker> checker) [member function]
    cls.add_method('DeserializeFromString', 
                   'bool', 
                   [param('std::string', 'value'), param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_virtual=True)
    ## ipv6-address.h (module 'network'): ns3::Ipv6Prefix ns3::Ipv6PrefixValue::Get() const [member function]
    cls.add_method('Get', 
                   'ns3::Ipv6Prefix', 
                   [], 
                   is_const=True)
    ## ipv6-address.h (module 'network'): std::string ns3::Ipv6PrefixValue::SerializeToString(ns3::Ptr<const ns3::AttributeChecker> checker) const [member function]
    cls.add_method('SerializeToString', 
                   'std::string', 
                   [param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_const=True, is_virtual=True)
    ## ipv6-address.h (module 'network'): void ns3::Ipv6PrefixValue::Set(ns3::Ipv6Prefix const & value) [member function]
    cls.add_method('Set', 
                   'void', 
                   [param('ns3::Ipv6Prefix const &', 'value')])
    return

def register_Ns3LogNormalRandomVariable_methods(root_module, cls):
    ## random-variable-stream.h (module 'core'): static ns3::TypeId ns3::LogNormalRandomVariable::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## random-variable-stream.h (module 'core'): ns3::LogNormalRandomVariable::LogNormalRandomVariable() [constructor]
    cls.add_constructor([])
    ## random-variable-stream.h (module 'core'): double ns3::LogNormalRandomVariable::GetMu() const [member function]
    cls.add_method('GetMu', 
                   'double', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::LogNormalRandomVariable::GetSigma() const [member function]
    cls.add_method('GetSigma', 
                   'double', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::LogNormalRandomVariable::GetValue(double mu, double sigma) [member function]
    cls.add_method('GetValue', 
                   'double', 
                   [param('double', 'mu'), param('double', 'sigma')])
    ## random-variable-stream.h (module 'core'): uint32_t ns3::LogNormalRandomVariable::GetInteger(uint32_t mu, uint32_t sigma) [member function]
    cls.add_method('GetInteger', 
                   'uint32_t', 
                   [param('uint32_t', 'mu'), param('uint32_t', 'sigma')])
    ## random-variable-stream.h (module 'core'): double ns3::LogNormalRandomVariable::GetValue() [member function]
    cls.add_method('GetValue', 
                   'double', 
                   [], 
                   is_virtual=True)
    ## random-variable-stream.h (module 'core'): uint32_t ns3::LogNormalRandomVariable::GetInteger() [member function]
    cls.add_method('GetInteger', 
                   'uint32_t', 
                   [], 
                   is_virtual=True)
    return

def register_Ns3Mac48AddressChecker_methods(root_module, cls):
    ## mac48-address.h (module 'network'): ns3::Mac48AddressChecker::Mac48AddressChecker() [constructor]
    cls.add_constructor([])
    ## mac48-address.h (module 'network'): ns3::Mac48AddressChecker::Mac48AddressChecker(ns3::Mac48AddressChecker const & arg0) [constructor]
    cls.add_constructor([param('ns3::Mac48AddressChecker const &', 'arg0')])
    return

def register_Ns3Mac48AddressValue_methods(root_module, cls):
    ## mac48-address.h (module 'network'): ns3::Mac48AddressValue::Mac48AddressValue() [constructor]
    cls.add_constructor([])
    ## mac48-address.h (module 'network'): ns3::Mac48AddressValue::Mac48AddressValue(ns3::Mac48Address const & value) [constructor]
    cls.add_constructor([param('ns3::Mac48Address const &', 'value')])
    ## mac48-address.h (module 'network'): ns3::Mac48AddressValue::Mac48AddressValue(ns3::Mac48AddressValue const & arg0) [constructor]
    cls.add_constructor([param('ns3::Mac48AddressValue const &', 'arg0')])
    ## mac48-address.h (module 'network'): ns3::Ptr<ns3::AttributeValue> ns3::Mac48AddressValue::Copy() const [member function]
    cls.add_method('Copy', 
                   'ns3::Ptr< ns3::AttributeValue >', 
                   [], 
                   is_const=True, is_virtual=True)
    ## mac48-address.h (module 'network'): bool ns3::Mac48AddressValue::DeserializeFromString(std::string value, ns3::Ptr<const ns3::AttributeChecker> checker) [member function]
    cls.add_method('DeserializeFromString', 
                   'bool', 
                   [param('std::string', 'value'), param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_virtual=True)
    ## mac48-address.h (module 'network'): ns3::Mac48Address ns3::Mac48AddressValue::Get() const [member function]
    cls.add_method('Get', 
                   'ns3::Mac48Address', 
                   [], 
                   is_const=True)
    ## mac48-address.h (module 'network'): std::string ns3::Mac48AddressValue::SerializeToString(ns3::Ptr<const ns3::AttributeChecker> checker) const [member function]
    cls.add_method('SerializeToString', 
                   'std::string', 
                   [param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_const=True, is_virtual=True)
    ## mac48-address.h (module 'network'): void ns3::Mac48AddressValue::Set(ns3::Mac48Address const & value) [member function]
    cls.add_method('Set', 
                   'void', 
                   [param('ns3::Mac48Address const &', 'value')])
    return

def register_Ns3NetDevice_methods(root_module, cls):
    ## net-device.h (module 'network'): ns3::NetDevice::NetDevice() [constructor]
    cls.add_constructor([])
    ## net-device.h (module 'network'): ns3::NetDevice::NetDevice(ns3::NetDevice const & arg0) [constructor]
    cls.add_constructor([param('ns3::NetDevice const &', 'arg0')])
    ## net-device.h (module 'network'): void ns3::NetDevice::AddLinkChangeCallback(ns3::Callback<void, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> callback) [member function]
    cls.add_method('AddLinkChangeCallback', 
                   'void', 
                   [param('ns3::Callback< void, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'callback')], 
                   is_pure_virtual=True, is_virtual=True)
    ## net-device.h (module 'network'): ns3::Address ns3::NetDevice::GetAddress() const [member function]
    cls.add_method('GetAddress', 
                   'ns3::Address', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## net-device.h (module 'network'): ns3::Address ns3::NetDevice::GetBroadcast() const [member function]
    cls.add_method('GetBroadcast', 
                   'ns3::Address', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## net-device.h (module 'network'): ns3::Ptr<ns3::Channel> ns3::NetDevice::GetChannel() const [member function]
    cls.add_method('GetChannel', 
                   'ns3::Ptr< ns3::Channel >', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## net-device.h (module 'network'): uint32_t ns3::NetDevice::GetIfIndex() const [member function]
    cls.add_method('GetIfIndex', 
                   'uint32_t', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## net-device.h (module 'network'): uint16_t ns3::NetDevice::GetMtu() const [member function]
    cls.add_method('GetMtu', 
                   'uint16_t', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## net-device.h (module 'network'): ns3::Address ns3::NetDevice::GetMulticast(ns3::Ipv4Address multicastGroup) const [member function]
    cls.add_method('GetMulticast', 
                   'ns3::Address', 
                   [param('ns3::Ipv4Address', 'multicastGroup')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## net-device.h (module 'network'): ns3::Address ns3::NetDevice::GetMulticast(ns3::Ipv6Address addr) const [member function]
    cls.add_method('GetMulticast', 
                   'ns3::Address', 
                   [param('ns3::Ipv6Address', 'addr')], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## net-device.h (module 'network'): ns3::Ptr<ns3::Node> ns3::NetDevice::GetNode() const [member function]
    cls.add_method('GetNode', 
                   'ns3::Ptr< ns3::Node >', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## net-device.h (module 'network'): static ns3::TypeId ns3::NetDevice::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## net-device.h (module 'network'): bool ns3::NetDevice::IsBridge() const [member function]
    cls.add_method('IsBridge', 
                   'bool', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## net-device.h (module 'network'): bool ns3::NetDevice::IsBroadcast() const [member function]
    cls.add_method('IsBroadcast', 
                   'bool', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## net-device.h (module 'network'): bool ns3::NetDevice::IsLinkUp() const [member function]
    cls.add_method('IsLinkUp', 
                   'bool', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## net-device.h (module 'network'): bool ns3::NetDevice::IsMulticast() const [member function]
    cls.add_method('IsMulticast', 
                   'bool', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## net-device.h (module 'network'): bool ns3::NetDevice::IsPointToPoint() const [member function]
    cls.add_method('IsPointToPoint', 
                   'bool', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## net-device.h (module 'network'): bool ns3::NetDevice::NeedsArp() const [member function]
    cls.add_method('NeedsArp', 
                   'bool', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## net-device.h (module 'network'): bool ns3::NetDevice::Send(ns3::Ptr<ns3::Packet> packet, ns3::Address const & dest, uint16_t protocolNumber) [member function]
    cls.add_method('Send', 
                   'bool', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('ns3::Address const &', 'dest'), param('uint16_t', 'protocolNumber')], 
                   is_pure_virtual=True, is_virtual=True)
    ## net-device.h (module 'network'): bool ns3::NetDevice::SendFrom(ns3::Ptr<ns3::Packet> packet, ns3::Address const & source, ns3::Address const & dest, uint16_t protocolNumber) [member function]
    cls.add_method('SendFrom', 
                   'bool', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('ns3::Address const &', 'source'), param('ns3::Address const &', 'dest'), param('uint16_t', 'protocolNumber')], 
                   is_pure_virtual=True, is_virtual=True)
    ## net-device.h (module 'network'): void ns3::NetDevice::SetAddress(ns3::Address address) [member function]
    cls.add_method('SetAddress', 
                   'void', 
                   [param('ns3::Address', 'address')], 
                   is_pure_virtual=True, is_virtual=True)
    ## net-device.h (module 'network'): void ns3::NetDevice::SetIfIndex(uint32_t const index) [member function]
    cls.add_method('SetIfIndex', 
                   'void', 
                   [param('uint32_t const', 'index')], 
                   is_pure_virtual=True, is_virtual=True)
    ## net-device.h (module 'network'): bool ns3::NetDevice::SetMtu(uint16_t const mtu) [member function]
    cls.add_method('SetMtu', 
                   'bool', 
                   [param('uint16_t const', 'mtu')], 
                   is_pure_virtual=True, is_virtual=True)
    ## net-device.h (module 'network'): void ns3::NetDevice::SetNode(ns3::Ptr<ns3::Node> node) [member function]
    cls.add_method('SetNode', 
                   'void', 
                   [param('ns3::Ptr< ns3::Node >', 'node')], 
                   is_pure_virtual=True, is_virtual=True)
    ## net-device.h (module 'network'): void ns3::NetDevice::SetPromiscReceiveCallback(ns3::NetDevice::PromiscReceiveCallback cb) [member function]
    cls.add_method('SetPromiscReceiveCallback', 
                   'void', 
                   [param('ns3::Callback< bool, ns3::Ptr< ns3::NetDevice >, ns3::Ptr< ns3::Packet const >, unsigned short, ns3::Address const &, ns3::Address const &, ns3::NetDevice::PacketType, ns3::empty, ns3::empty, ns3::empty >', 'cb')], 
                   is_pure_virtual=True, is_virtual=True)
    ## net-device.h (module 'network'): void ns3::NetDevice::SetReceiveCallback(ns3::NetDevice::ReceiveCallback cb) [member function]
    cls.add_method('SetReceiveCallback', 
                   'void', 
                   [param('ns3::Callback< bool, ns3::Ptr< ns3::NetDevice >, ns3::Ptr< ns3::Packet const >, unsigned short, ns3::Address const &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'cb')], 
                   is_pure_virtual=True, is_virtual=True)
    ## net-device.h (module 'network'): bool ns3::NetDevice::SupportsSendFrom() const [member function]
    cls.add_method('SupportsSendFrom', 
                   'bool', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    return

def register_Ns3NixVector_methods(root_module, cls):
    cls.add_output_stream_operator()
    ## nix-vector.h (module 'network'): ns3::NixVector::NixVector() [constructor]
    cls.add_constructor([])
    ## nix-vector.h (module 'network'): ns3::NixVector::NixVector(ns3::NixVector const & o) [constructor]
    cls.add_constructor([param('ns3::NixVector const &', 'o')])
    ## nix-vector.h (module 'network'): void ns3::NixVector::AddNeighborIndex(uint32_t newBits, uint32_t numberOfBits) [member function]
    cls.add_method('AddNeighborIndex', 
                   'void', 
                   [param('uint32_t', 'newBits'), param('uint32_t', 'numberOfBits')])
    ## nix-vector.h (module 'network'): uint32_t ns3::NixVector::BitCount(uint32_t numberOfNeighbors) const [member function]
    cls.add_method('BitCount', 
                   'uint32_t', 
                   [param('uint32_t', 'numberOfNeighbors')], 
                   is_const=True)
    ## nix-vector.h (module 'network'): ns3::Ptr<ns3::NixVector> ns3::NixVector::Copy() const [member function]
    cls.add_method('Copy', 
                   'ns3::Ptr< ns3::NixVector >', 
                   [], 
                   is_const=True)
    ## nix-vector.h (module 'network'): uint32_t ns3::NixVector::Deserialize(uint32_t const * buffer, uint32_t size) [member function]
    cls.add_method('Deserialize', 
                   'uint32_t', 
                   [param('uint32_t const *', 'buffer'), param('uint32_t', 'size')])
    ## nix-vector.h (module 'network'): uint32_t ns3::NixVector::ExtractNeighborIndex(uint32_t numberOfBits) [member function]
    cls.add_method('ExtractNeighborIndex', 
                   'uint32_t', 
                   [param('uint32_t', 'numberOfBits')])
    ## nix-vector.h (module 'network'): uint32_t ns3::NixVector::GetRemainingBits() [member function]
    cls.add_method('GetRemainingBits', 
                   'uint32_t', 
                   [])
    ## nix-vector.h (module 'network'): uint32_t ns3::NixVector::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## nix-vector.h (module 'network'): uint32_t ns3::NixVector::Serialize(uint32_t * buffer, uint32_t maxSize) const [member function]
    cls.add_method('Serialize', 
                   'uint32_t', 
                   [param('uint32_t *', 'buffer'), param('uint32_t', 'maxSize')], 
                   is_const=True)
    return

def register_Ns3Node_methods(root_module, cls):
    ## node.h (module 'network'): ns3::Node::Node(ns3::Node const & arg0) [constructor]
    cls.add_constructor([param('ns3::Node const &', 'arg0')])
    ## node.h (module 'network'): ns3::Node::Node() [constructor]
    cls.add_constructor([])
    ## node.h (module 'network'): ns3::Node::Node(uint32_t systemId) [constructor]
    cls.add_constructor([param('uint32_t', 'systemId')])
    ## node.h (module 'network'): uint32_t ns3::Node::AddApplication(ns3::Ptr<ns3::Application> application) [member function]
    cls.add_method('AddApplication', 
                   'uint32_t', 
                   [param('ns3::Ptr< ns3::Application >', 'application')])
    ## node.h (module 'network'): uint32_t ns3::Node::AddDevice(ns3::Ptr<ns3::NetDevice> device) [member function]
    cls.add_method('AddDevice', 
                   'uint32_t', 
                   [param('ns3::Ptr< ns3::NetDevice >', 'device')])
    ## node.h (module 'network'): static bool ns3::Node::ChecksumEnabled() [member function]
    cls.add_method('ChecksumEnabled', 
                   'bool', 
                   [], 
                   is_static=True)
    ## node.h (module 'network'): ns3::Ptr<ns3::Application> ns3::Node::GetApplication(uint32_t index) const [member function]
    cls.add_method('GetApplication', 
                   'ns3::Ptr< ns3::Application >', 
                   [param('uint32_t', 'index')], 
                   is_const=True)
    ## node.h (module 'network'): ns3::Ptr<ns3::NetDevice> ns3::Node::GetDevice(uint32_t index) const [member function]
    cls.add_method('GetDevice', 
                   'ns3::Ptr< ns3::NetDevice >', 
                   [param('uint32_t', 'index')], 
                   is_const=True)
    ## node.h (module 'network'): uint32_t ns3::Node::GetId() const [member function]
    cls.add_method('GetId', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## node.h (module 'network'): ns3::Time ns3::Node::GetLocalTime() const [member function]
    cls.add_method('GetLocalTime', 
                   'ns3::Time', 
                   [], 
                   is_const=True)
    ## node.h (module 'network'): uint32_t ns3::Node::GetNApplications() const [member function]
    cls.add_method('GetNApplications', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## node.h (module 'network'): uint32_t ns3::Node::GetNDevices() const [member function]
    cls.add_method('GetNDevices', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## node.h (module 'network'): uint32_t ns3::Node::GetSystemId() const [member function]
    cls.add_method('GetSystemId', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## node.h (module 'network'): static ns3::TypeId ns3::Node::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## node.h (module 'network'): void ns3::Node::RegisterDeviceAdditionListener(ns3::Node::DeviceAdditionListener listener) [member function]
    cls.add_method('RegisterDeviceAdditionListener', 
                   'void', 
                   [param('ns3::Callback< void, ns3::Ptr< ns3::NetDevice >, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'listener')])
    ## node.h (module 'network'): void ns3::Node::RegisterProtocolHandler(ns3::Node::ProtocolHandler handler, uint16_t protocolType, ns3::Ptr<ns3::NetDevice> device, bool promiscuous=false) [member function]
    cls.add_method('RegisterProtocolHandler', 
                   'void', 
                   [param('ns3::Callback< void, ns3::Ptr< ns3::NetDevice >, ns3::Ptr< ns3::Packet const >, unsigned short, ns3::Address const &, ns3::Address const &, ns3::NetDevice::PacketType, ns3::empty, ns3::empty, ns3::empty >', 'handler'), param('uint16_t', 'protocolType'), param('ns3::Ptr< ns3::NetDevice >', 'device'), param('bool', 'promiscuous', default_value='false')])
    ## node.h (module 'network'): void ns3::Node::UnregisterDeviceAdditionListener(ns3::Node::DeviceAdditionListener listener) [member function]
    cls.add_method('UnregisterDeviceAdditionListener', 
                   'void', 
                   [param('ns3::Callback< void, ns3::Ptr< ns3::NetDevice >, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'listener')])
    ## node.h (module 'network'): void ns3::Node::UnregisterProtocolHandler(ns3::Node::ProtocolHandler handler) [member function]
    cls.add_method('UnregisterProtocolHandler', 
                   'void', 
                   [param('ns3::Callback< void, ns3::Ptr< ns3::NetDevice >, ns3::Ptr< ns3::Packet const >, unsigned short, ns3::Address const &, ns3::Address const &, ns3::NetDevice::PacketType, ns3::empty, ns3::empty, ns3::empty >', 'handler')])
    ## node.h (module 'network'): void ns3::Node::DoDispose() [member function]
    cls.add_method('DoDispose', 
                   'void', 
                   [], 
                   visibility='protected', is_virtual=True)
    ## node.h (module 'network'): void ns3::Node::DoInitialize() [member function]
    cls.add_method('DoInitialize', 
                   'void', 
                   [], 
                   visibility='protected', is_virtual=True)
    return

def register_Ns3NormalRandomVariable_methods(root_module, cls):
    ## random-variable-stream.h (module 'core'): ns3::NormalRandomVariable::INFINITE_VALUE [variable]
    cls.add_static_attribute('INFINITE_VALUE', 'double const', is_const=True)
    ## random-variable-stream.h (module 'core'): static ns3::TypeId ns3::NormalRandomVariable::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## random-variable-stream.h (module 'core'): ns3::NormalRandomVariable::NormalRandomVariable() [constructor]
    cls.add_constructor([])
    ## random-variable-stream.h (module 'core'): double ns3::NormalRandomVariable::GetMean() const [member function]
    cls.add_method('GetMean', 
                   'double', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::NormalRandomVariable::GetVariance() const [member function]
    cls.add_method('GetVariance', 
                   'double', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::NormalRandomVariable::GetBound() const [member function]
    cls.add_method('GetBound', 
                   'double', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::NormalRandomVariable::GetValue(double mean, double variance, double bound=ns3::NormalRandomVariable::INFINITE_VALUE) [member function]
    cls.add_method('GetValue', 
                   'double', 
                   [param('double', 'mean'), param('double', 'variance'), param('double', 'bound', default_value='ns3::NormalRandomVariable::INFINITE_VALUE')])
    ## random-variable-stream.h (module 'core'): uint32_t ns3::NormalRandomVariable::GetInteger(uint32_t mean, uint32_t variance, uint32_t bound) [member function]
    cls.add_method('GetInteger', 
                   'uint32_t', 
                   [param('uint32_t', 'mean'), param('uint32_t', 'variance'), param('uint32_t', 'bound')])
    ## random-variable-stream.h (module 'core'): double ns3::NormalRandomVariable::GetValue() [member function]
    cls.add_method('GetValue', 
                   'double', 
                   [], 
                   is_virtual=True)
    ## random-variable-stream.h (module 'core'): uint32_t ns3::NormalRandomVariable::GetInteger() [member function]
    cls.add_method('GetInteger', 
                   'uint32_t', 
                   [], 
                   is_virtual=True)
    return

def register_Ns3ObjectFactoryChecker_methods(root_module, cls):
    ## object-factory.h (module 'core'): ns3::ObjectFactoryChecker::ObjectFactoryChecker() [constructor]
    cls.add_constructor([])
    ## object-factory.h (module 'core'): ns3::ObjectFactoryChecker::ObjectFactoryChecker(ns3::ObjectFactoryChecker const & arg0) [constructor]
    cls.add_constructor([param('ns3::ObjectFactoryChecker const &', 'arg0')])
    return

def register_Ns3ObjectFactoryValue_methods(root_module, cls):
    ## object-factory.h (module 'core'): ns3::ObjectFactoryValue::ObjectFactoryValue() [constructor]
    cls.add_constructor([])
    ## object-factory.h (module 'core'): ns3::ObjectFactoryValue::ObjectFactoryValue(ns3::ObjectFactory const & value) [constructor]
    cls.add_constructor([param('ns3::ObjectFactory const &', 'value')])
    ## object-factory.h (module 'core'): ns3::ObjectFactoryValue::ObjectFactoryValue(ns3::ObjectFactoryValue const & arg0) [constructor]
    cls.add_constructor([param('ns3::ObjectFactoryValue const &', 'arg0')])
    ## object-factory.h (module 'core'): ns3::Ptr<ns3::AttributeValue> ns3::ObjectFactoryValue::Copy() const [member function]
    cls.add_method('Copy', 
                   'ns3::Ptr< ns3::AttributeValue >', 
                   [], 
                   is_const=True, is_virtual=True)
    ## object-factory.h (module 'core'): bool ns3::ObjectFactoryValue::DeserializeFromString(std::string value, ns3::Ptr<const ns3::AttributeChecker> checker) [member function]
    cls.add_method('DeserializeFromString', 
                   'bool', 
                   [param('std::string', 'value'), param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_virtual=True)
    ## object-factory.h (module 'core'): ns3::ObjectFactory ns3::ObjectFactoryValue::Get() const [member function]
    cls.add_method('Get', 
                   'ns3::ObjectFactory', 
                   [], 
                   is_const=True)
    ## object-factory.h (module 'core'): std::string ns3::ObjectFactoryValue::SerializeToString(ns3::Ptr<const ns3::AttributeChecker> checker) const [member function]
    cls.add_method('SerializeToString', 
                   'std::string', 
                   [param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_const=True, is_virtual=True)
    ## object-factory.h (module 'core'): void ns3::ObjectFactoryValue::Set(ns3::ObjectFactory const & value) [member function]
    cls.add_method('Set', 
                   'void', 
                   [param('ns3::ObjectFactory const &', 'value')])
    return

def register_Ns3OutputStreamWrapper_methods(root_module, cls):
    ## output-stream-wrapper.h (module 'network'): ns3::OutputStreamWrapper::OutputStreamWrapper(ns3::OutputStreamWrapper const & arg0) [constructor]
    cls.add_constructor([param('ns3::OutputStreamWrapper const &', 'arg0')])
    ## output-stream-wrapper.h (module 'network'): ns3::OutputStreamWrapper::OutputStreamWrapper(std::string filename, std::ios_base::openmode filemode) [constructor]
    cls.add_constructor([param('std::string', 'filename'), param('std::ios_base::openmode', 'filemode')])
    ## output-stream-wrapper.h (module 'network'): ns3::OutputStreamWrapper::OutputStreamWrapper(std::ostream * os) [constructor]
    cls.add_constructor([param('std::ostream *', 'os')])
    ## output-stream-wrapper.h (module 'network'): std::ostream * ns3::OutputStreamWrapper::GetStream() [member function]
    cls.add_method('GetStream', 
                   'std::ostream *', 
                   [])
    return

def register_Ns3Packet_methods(root_module, cls):
    cls.add_output_stream_operator()
    ## packet.h (module 'network'): ns3::Packet::Packet() [constructor]
    cls.add_constructor([])
    ## packet.h (module 'network'): ns3::Packet::Packet(ns3::Packet const & o) [constructor]
    cls.add_constructor([param('ns3::Packet const &', 'o')])
    ## packet.h (module 'network'): ns3::Packet::Packet(uint32_t size) [constructor]
    cls.add_constructor([param('uint32_t', 'size')])
    ## packet.h (module 'network'): ns3::Packet::Packet(uint8_t const * buffer, uint32_t size, bool magic) [constructor]
    cls.add_constructor([param('uint8_t const *', 'buffer'), param('uint32_t', 'size'), param('bool', 'magic')])
    ## packet.h (module 'network'): ns3::Packet::Packet(uint8_t const * buffer, uint32_t size) [constructor]
    cls.add_constructor([param('uint8_t const *', 'buffer'), param('uint32_t', 'size')])
    ## packet.h (module 'network'): void ns3::Packet::AddAtEnd(ns3::Ptr<const ns3::Packet> packet) [member function]
    cls.add_method('AddAtEnd', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet const >', 'packet')])
    ## packet.h (module 'network'): void ns3::Packet::AddByteTag(ns3::Tag const & tag) const [member function]
    cls.add_method('AddByteTag', 
                   'void', 
                   [param('ns3::Tag const &', 'tag')], 
                   is_const=True)
    ## packet.h (module 'network'): void ns3::Packet::AddHeader(ns3::Header const & header) [member function]
    cls.add_method('AddHeader', 
                   'void', 
                   [param('ns3::Header const &', 'header')])
    ## packet.h (module 'network'): void ns3::Packet::AddPacketTag(ns3::Tag const & tag) const [member function]
    cls.add_method('AddPacketTag', 
                   'void', 
                   [param('ns3::Tag const &', 'tag')], 
                   is_const=True)
    ## packet.h (module 'network'): void ns3::Packet::AddPaddingAtEnd(uint32_t size) [member function]
    cls.add_method('AddPaddingAtEnd', 
                   'void', 
                   [param('uint32_t', 'size')])
    ## packet.h (module 'network'): void ns3::Packet::AddTrailer(ns3::Trailer const & trailer) [member function]
    cls.add_method('AddTrailer', 
                   'void', 
                   [param('ns3::Trailer const &', 'trailer')])
    ## packet.h (module 'network'): ns3::PacketMetadata::ItemIterator ns3::Packet::BeginItem() const [member function]
    cls.add_method('BeginItem', 
                   'ns3::PacketMetadata::ItemIterator', 
                   [], 
                   is_const=True)
    ## packet.h (module 'network'): ns3::Ptr<ns3::Packet> ns3::Packet::Copy() const [member function]
    cls.add_method('Copy', 
                   'ns3::Ptr< ns3::Packet >', 
                   [], 
                   is_const=True)
    ## packet.h (module 'network'): uint32_t ns3::Packet::CopyData(uint8_t * buffer, uint32_t size) const [member function]
    cls.add_method('CopyData', 
                   'uint32_t', 
                   [param('uint8_t *', 'buffer'), param('uint32_t', 'size')], 
                   is_const=True)
    ## packet.h (module 'network'): void ns3::Packet::CopyData(std::ostream * os, uint32_t size) const [member function]
    cls.add_method('CopyData', 
                   'void', 
                   [param('std::ostream *', 'os'), param('uint32_t', 'size')], 
                   is_const=True)
    ## packet.h (module 'network'): ns3::Ptr<ns3::Packet> ns3::Packet::CreateFragment(uint32_t start, uint32_t length) const [member function]
    cls.add_method('CreateFragment', 
                   'ns3::Ptr< ns3::Packet >', 
                   [param('uint32_t', 'start'), param('uint32_t', 'length')], 
                   is_const=True)
    ## packet.h (module 'network'): static void ns3::Packet::EnableChecking() [member function]
    cls.add_method('EnableChecking', 
                   'void', 
                   [], 
                   is_static=True)
    ## packet.h (module 'network'): static void ns3::Packet::EnablePrinting() [member function]
    cls.add_method('EnablePrinting', 
                   'void', 
                   [], 
                   is_static=True)
    ## packet.h (module 'network'): bool ns3::Packet::FindFirstMatchingByteTag(ns3::Tag & tag) const [member function]
    cls.add_method('FindFirstMatchingByteTag', 
                   'bool', 
                   [param('ns3::Tag &', 'tag')], 
                   is_const=True)
    ## packet.h (module 'network'): ns3::ByteTagIterator ns3::Packet::GetByteTagIterator() const [member function]
    cls.add_method('GetByteTagIterator', 
                   'ns3::ByteTagIterator', 
                   [], 
                   is_const=True)
    ## packet.h (module 'network'): ns3::Ptr<ns3::NixVector> ns3::Packet::GetNixVector() const [member function]
    cls.add_method('GetNixVector', 
                   'ns3::Ptr< ns3::NixVector >', 
                   [], 
                   is_const=True)
    ## packet.h (module 'network'): ns3::PacketTagIterator ns3::Packet::GetPacketTagIterator() const [member function]
    cls.add_method('GetPacketTagIterator', 
                   'ns3::PacketTagIterator', 
                   [], 
                   is_const=True)
    ## packet.h (module 'network'): uint32_t ns3::Packet::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## packet.h (module 'network'): uint32_t ns3::Packet::GetSize() const [member function]
    cls.add_method('GetSize', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## packet.h (module 'network'): uint64_t ns3::Packet::GetUid() const [member function]
    cls.add_method('GetUid', 
                   'uint64_t', 
                   [], 
                   is_const=True)
    ## packet.h (module 'network'): uint32_t ns3::Packet::PeekHeader(ns3::Header & header) const [member function]
    cls.add_method('PeekHeader', 
                   'uint32_t', 
                   [param('ns3::Header &', 'header')], 
                   is_const=True)
    ## packet.h (module 'network'): uint32_t ns3::Packet::PeekHeader(ns3::Header & header, uint32_t size) const [member function]
    cls.add_method('PeekHeader', 
                   'uint32_t', 
                   [param('ns3::Header &', 'header'), param('uint32_t', 'size')], 
                   is_const=True)
    ## packet.h (module 'network'): bool ns3::Packet::PeekPacketTag(ns3::Tag & tag) const [member function]
    cls.add_method('PeekPacketTag', 
                   'bool', 
                   [param('ns3::Tag &', 'tag')], 
                   is_const=True)
    ## packet.h (module 'network'): uint32_t ns3::Packet::PeekTrailer(ns3::Trailer & trailer) [member function]
    cls.add_method('PeekTrailer', 
                   'uint32_t', 
                   [param('ns3::Trailer &', 'trailer')])
    ## packet.h (module 'network'): void ns3::Packet::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True)
    ## packet.h (module 'network'): void ns3::Packet::PrintByteTags(std::ostream & os) const [member function]
    cls.add_method('PrintByteTags', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True)
    ## packet.h (module 'network'): void ns3::Packet::PrintPacketTags(std::ostream & os) const [member function]
    cls.add_method('PrintPacketTags', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True)
    ## packet.h (module 'network'): void ns3::Packet::RemoveAllByteTags() [member function]
    cls.add_method('RemoveAllByteTags', 
                   'void', 
                   [])
    ## packet.h (module 'network'): void ns3::Packet::RemoveAllPacketTags() [member function]
    cls.add_method('RemoveAllPacketTags', 
                   'void', 
                   [])
    ## packet.h (module 'network'): void ns3::Packet::RemoveAtEnd(uint32_t size) [member function]
    cls.add_method('RemoveAtEnd', 
                   'void', 
                   [param('uint32_t', 'size')])
    ## packet.h (module 'network'): void ns3::Packet::RemoveAtStart(uint32_t size) [member function]
    cls.add_method('RemoveAtStart', 
                   'void', 
                   [param('uint32_t', 'size')])
    ## packet.h (module 'network'): uint32_t ns3::Packet::RemoveHeader(ns3::Header & header) [member function]
    cls.add_method('RemoveHeader', 
                   'uint32_t', 
                   [param('ns3::Header &', 'header')])
    ## packet.h (module 'network'): uint32_t ns3::Packet::RemoveHeader(ns3::Header & header, uint32_t size) [member function]
    cls.add_method('RemoveHeader', 
                   'uint32_t', 
                   [param('ns3::Header &', 'header'), param('uint32_t', 'size')])
    ## packet.h (module 'network'): bool ns3::Packet::RemovePacketTag(ns3::Tag & tag) [member function]
    cls.add_method('RemovePacketTag', 
                   'bool', 
                   [param('ns3::Tag &', 'tag')])
    ## packet.h (module 'network'): uint32_t ns3::Packet::RemoveTrailer(ns3::Trailer & trailer) [member function]
    cls.add_method('RemoveTrailer', 
                   'uint32_t', 
                   [param('ns3::Trailer &', 'trailer')])
    ## packet.h (module 'network'): bool ns3::Packet::ReplacePacketTag(ns3::Tag & tag) [member function]
    cls.add_method('ReplacePacketTag', 
                   'bool', 
                   [param('ns3::Tag &', 'tag')])
    ## packet.h (module 'network'): uint32_t ns3::Packet::Serialize(uint8_t * buffer, uint32_t maxSize) const [member function]
    cls.add_method('Serialize', 
                   'uint32_t', 
                   [param('uint8_t *', 'buffer'), param('uint32_t', 'maxSize')], 
                   is_const=True)
    ## packet.h (module 'network'): void ns3::Packet::SetNixVector(ns3::Ptr<ns3::NixVector> nixVector) [member function]
    cls.add_method('SetNixVector', 
                   'void', 
                   [param('ns3::Ptr< ns3::NixVector >', 'nixVector')])
    ## packet.h (module 'network'): std::string ns3::Packet::ToString() const [member function]
    cls.add_method('ToString', 
                   'std::string', 
                   [], 
                   is_const=True)
    return

def register_Ns3ParetoRandomVariable_methods(root_module, cls):
    ## random-variable-stream.h (module 'core'): static ns3::TypeId ns3::ParetoRandomVariable::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## random-variable-stream.h (module 'core'): ns3::ParetoRandomVariable::ParetoRandomVariable() [constructor]
    cls.add_constructor([])
    ## random-variable-stream.h (module 'core'): double ns3::ParetoRandomVariable::GetMean() const [member function]
    cls.add_method('GetMean', 
                   'double', 
                   [], 
                   deprecated=True, is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::ParetoRandomVariable::GetScale() const [member function]
    cls.add_method('GetScale', 
                   'double', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::ParetoRandomVariable::GetShape() const [member function]
    cls.add_method('GetShape', 
                   'double', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::ParetoRandomVariable::GetBound() const [member function]
    cls.add_method('GetBound', 
                   'double', 
                   [], 
                   is_const=True)
    ## random-variable-stream.h (module 'core'): double ns3::ParetoRandomVariable::GetValue(double scale, double shape, double bound) [member function]
    cls.add_method('GetValue', 
                   'double', 
                   [param('double', 'scale'), param('double', 'shape'), param('double', 'bound')])
    ## random-variable-stream.h (module 'core'): uint32_t ns3::ParetoRandomVariable::GetInteger(uint32_t scale, uint32_t shape, uint32_t bound) [member function]
    cls.add_method('GetInteger', 
                   'uint32_t', 
                   [param('uint32_t', 'scale'), param('uint32_t', 'shape'), param('uint32_t', 'bound')])
    ## random-variable-stream.h (module 'core'): double ns3::ParetoRandomVariable::GetValue() [member function]
    cls.add_method('GetValue', 
                   'double', 
                   [], 
                   is_virtual=True)
    ## random-variable-stream.h (module 'core'): uint32_t ns3::ParetoRandomVariable::GetInteger() [member function]
    cls.add_method('GetInteger', 
                   'uint32_t', 
                   [], 
                   is_virtual=True)
    return

def register_Ns3TcpL4Protocol_methods(root_module, cls):
    ## tcp-l4-protocol.h (module 'internet'): static ns3::TypeId ns3::TcpL4Protocol::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## tcp-l4-protocol.h (module 'internet'): ns3::TcpL4Protocol::PROT_NUMBER [variable]
    cls.add_static_attribute('PROT_NUMBER', 'uint8_t const', is_const=True)
    ## tcp-l4-protocol.h (module 'internet'): ns3::TcpL4Protocol::TcpL4Protocol() [constructor]
    cls.add_constructor([])
    ## tcp-l4-protocol.h (module 'internet'): void ns3::TcpL4Protocol::SetNode(ns3::Ptr<ns3::Node> node) [member function]
    cls.add_method('SetNode', 
                   'void', 
                   [param('ns3::Ptr< ns3::Node >', 'node')])
    ## tcp-l4-protocol.h (module 'internet'): ns3::Ptr<ns3::Socket> ns3::TcpL4Protocol::CreateSocket() [member function]
    cls.add_method('CreateSocket', 
                   'ns3::Ptr< ns3::Socket >', 
                   [])
    ## tcp-l4-protocol.h (module 'internet'): ns3::Ptr<ns3::Socket> ns3::TcpL4Protocol::CreateSocket(ns3::TypeId congestionTypeId, ns3::TypeId recoveryTypeId) [member function]
    cls.add_method('CreateSocket', 
                   'ns3::Ptr< ns3::Socket >', 
                   [param('ns3::TypeId', 'congestionTypeId'), param('ns3::TypeId', 'recoveryTypeId')])
    ## tcp-l4-protocol.h (module 'internet'): ns3::Ptr<ns3::Socket> ns3::TcpL4Protocol::CreateSocket(ns3::TypeId congestionTypeId) [member function]
    cls.add_method('CreateSocket', 
                   'ns3::Ptr< ns3::Socket >', 
                   [param('ns3::TypeId', 'congestionTypeId')])
    ## tcp-l4-protocol.h (module 'internet'): ns3::Ipv4EndPoint * ns3::TcpL4Protocol::Allocate() [member function]
    cls.add_method('Allocate', 
                   'ns3::Ipv4EndPoint *', 
                   [])
    ## tcp-l4-protocol.h (module 'internet'): ns3::Ipv4EndPoint * ns3::TcpL4Protocol::Allocate(ns3::Ipv4Address address) [member function]
    cls.add_method('Allocate', 
                   'ns3::Ipv4EndPoint *', 
                   [param('ns3::Ipv4Address', 'address')])
    ## tcp-l4-protocol.h (module 'internet'): ns3::Ipv4EndPoint * ns3::TcpL4Protocol::Allocate(ns3::Ptr<ns3::NetDevice> boundNetDevice, uint16_t port) [member function]
    cls.add_method('Allocate', 
                   'ns3::Ipv4EndPoint *', 
                   [param('ns3::Ptr< ns3::NetDevice >', 'boundNetDevice'), param('uint16_t', 'port')])
    ## tcp-l4-protocol.h (module 'internet'): ns3::Ipv4EndPoint * ns3::TcpL4Protocol::Allocate(ns3::Ptr<ns3::NetDevice> boundNetDevice, ns3::Ipv4Address address, uint16_t port) [member function]
    cls.add_method('Allocate', 
                   'ns3::Ipv4EndPoint *', 
                   [param('ns3::Ptr< ns3::NetDevice >', 'boundNetDevice'), param('ns3::Ipv4Address', 'address'), param('uint16_t', 'port')])
    ## tcp-l4-protocol.h (module 'internet'): ns3::Ipv4EndPoint * ns3::TcpL4Protocol::Allocate(ns3::Ptr<ns3::NetDevice> boundNetDevice, ns3::Ipv4Address localAddress, uint16_t localPort, ns3::Ipv4Address peerAddress, uint16_t peerPort) [member function]
    cls.add_method('Allocate', 
                   'ns3::Ipv4EndPoint *', 
                   [param('ns3::Ptr< ns3::NetDevice >', 'boundNetDevice'), param('ns3::Ipv4Address', 'localAddress'), param('uint16_t', 'localPort'), param('ns3::Ipv4Address', 'peerAddress'), param('uint16_t', 'peerPort')])
    ## tcp-l4-protocol.h (module 'internet'): ns3::Ipv6EndPoint * ns3::TcpL4Protocol::Allocate6() [member function]
    cls.add_method('Allocate6', 
                   'ns3::Ipv6EndPoint *', 
                   [])
    ## tcp-l4-protocol.h (module 'internet'): ns3::Ipv6EndPoint * ns3::TcpL4Protocol::Allocate6(ns3::Ipv6Address address) [member function]
    cls.add_method('Allocate6', 
                   'ns3::Ipv6EndPoint *', 
                   [param('ns3::Ipv6Address', 'address')])
    ## tcp-l4-protocol.h (module 'internet'): ns3::Ipv6EndPoint * ns3::TcpL4Protocol::Allocate6(ns3::Ptr<ns3::NetDevice> boundNetDevice, uint16_t port) [member function]
    cls.add_method('Allocate6', 
                   'ns3::Ipv6EndPoint *', 
                   [param('ns3::Ptr< ns3::NetDevice >', 'boundNetDevice'), param('uint16_t', 'port')])
    ## tcp-l4-protocol.h (module 'internet'): ns3::Ipv6EndPoint * ns3::TcpL4Protocol::Allocate6(ns3::Ptr<ns3::NetDevice> boundNetDevice, ns3::Ipv6Address address, uint16_t port) [member function]
    cls.add_method('Allocate6', 
                   'ns3::Ipv6EndPoint *', 
                   [param('ns3::Ptr< ns3::NetDevice >', 'boundNetDevice'), param('ns3::Ipv6Address', 'address'), param('uint16_t', 'port')])
    ## tcp-l4-protocol.h (module 'internet'): ns3::Ipv6EndPoint * ns3::TcpL4Protocol::Allocate6(ns3::Ptr<ns3::NetDevice> boundNetDevice, ns3::Ipv6Address localAddress, uint16_t localPort, ns3::Ipv6Address peerAddress, uint16_t peerPort) [member function]
    cls.add_method('Allocate6', 
                   'ns3::Ipv6EndPoint *', 
                   [param('ns3::Ptr< ns3::NetDevice >', 'boundNetDevice'), param('ns3::Ipv6Address', 'localAddress'), param('uint16_t', 'localPort'), param('ns3::Ipv6Address', 'peerAddress'), param('uint16_t', 'peerPort')])
    ## tcp-l4-protocol.h (module 'internet'): void ns3::TcpL4Protocol::SendPacket(ns3::Ptr<ns3::Packet> pkt, ns3::TcpHeader const & outgoing, ns3::Address const & saddr, ns3::Address const & daddr, ns3::Ptr<ns3::NetDevice> oif=0) const [member function]
    cls.add_method('SendPacket', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet >', 'pkt'), param('ns3::TcpHeader const &', 'outgoing'), param('ns3::Address const &', 'saddr'), param('ns3::Address const &', 'daddr'), param('ns3::Ptr< ns3::NetDevice >', 'oif', default_value='0')], 
                   is_const=True)
    ## tcp-l4-protocol.h (module 'internet'): void ns3::TcpL4Protocol::AddSocket(ns3::Ptr<ns3::TcpSocketBase> socket) [member function]
    cls.add_method('AddSocket', 
                   'void', 
                   [param('ns3::Ptr< ns3::TcpSocketBase >', 'socket')])
    ## tcp-l4-protocol.h (module 'internet'): bool ns3::TcpL4Protocol::RemoveSocket(ns3::Ptr<ns3::TcpSocketBase> socket) [member function]
    cls.add_method('RemoveSocket', 
                   'bool', 
                   [param('ns3::Ptr< ns3::TcpSocketBase >', 'socket')])
    ## tcp-l4-protocol.h (module 'internet'): void ns3::TcpL4Protocol::DeAllocate(ns3::Ipv4EndPoint * endPoint) [member function]
    cls.add_method('DeAllocate', 
                   'void', 
                   [param('ns3::Ipv4EndPoint *', 'endPoint')])
    ## tcp-l4-protocol.h (module 'internet'): void ns3::TcpL4Protocol::DeAllocate(ns3::Ipv6EndPoint * endPoint) [member function]
    cls.add_method('DeAllocate', 
                   'void', 
                   [param('ns3::Ipv6EndPoint *', 'endPoint')])
    ## tcp-l4-protocol.h (module 'internet'): ns3::IpL4Protocol::RxStatus ns3::TcpL4Protocol::Receive(ns3::Ptr<ns3::Packet> p, ns3::Ipv4Header const & incomingIpHeader, ns3::Ptr<ns3::Ipv4Interface> incomingInterface) [member function]
    cls.add_method('Receive', 
                   'ns3::IpL4Protocol::RxStatus', 
                   [param('ns3::Ptr< ns3::Packet >', 'p'), param('ns3::Ipv4Header const &', 'incomingIpHeader'), param('ns3::Ptr< ns3::Ipv4Interface >', 'incomingInterface')], 
                   is_virtual=True)
    ## tcp-l4-protocol.h (module 'internet'): ns3::IpL4Protocol::RxStatus ns3::TcpL4Protocol::Receive(ns3::Ptr<ns3::Packet> p, ns3::Ipv6Header const & incomingIpHeader, ns3::Ptr<ns3::Ipv6Interface> incomingInterface) [member function]
    cls.add_method('Receive', 
                   'ns3::IpL4Protocol::RxStatus', 
                   [param('ns3::Ptr< ns3::Packet >', 'p'), param('ns3::Ipv6Header const &', 'incomingIpHeader'), param('ns3::Ptr< ns3::Ipv6Interface >', 'incomingInterface')], 
                   is_virtual=True)
    ## tcp-l4-protocol.h (module 'internet'): void ns3::TcpL4Protocol::ReceiveIcmp(ns3::Ipv4Address icmpSource, uint8_t icmpTtl, uint8_t icmpType, uint8_t icmpCode, uint32_t icmpInfo, ns3::Ipv4Address payloadSource, ns3::Ipv4Address payloadDestination, uint8_t const * payload) [member function]
    cls.add_method('ReceiveIcmp', 
                   'void', 
                   [param('ns3::Ipv4Address', 'icmpSource'), param('uint8_t', 'icmpTtl'), param('uint8_t', 'icmpType'), param('uint8_t', 'icmpCode'), param('uint32_t', 'icmpInfo'), param('ns3::Ipv4Address', 'payloadSource'), param('ns3::Ipv4Address', 'payloadDestination'), param('uint8_t const *', 'payload')], 
                   is_virtual=True)
    ## tcp-l4-protocol.h (module 'internet'): void ns3::TcpL4Protocol::ReceiveIcmp(ns3::Ipv6Address icmpSource, uint8_t icmpTtl, uint8_t icmpType, uint8_t icmpCode, uint32_t icmpInfo, ns3::Ipv6Address payloadSource, ns3::Ipv6Address payloadDestination, uint8_t const * payload) [member function]
    cls.add_method('ReceiveIcmp', 
                   'void', 
                   [param('ns3::Ipv6Address', 'icmpSource'), param('uint8_t', 'icmpTtl'), param('uint8_t', 'icmpType'), param('uint8_t', 'icmpCode'), param('uint32_t', 'icmpInfo'), param('ns3::Ipv6Address', 'payloadSource'), param('ns3::Ipv6Address', 'payloadDestination'), param('uint8_t const *', 'payload')], 
                   is_virtual=True)
    ## tcp-l4-protocol.h (module 'internet'): void ns3::TcpL4Protocol::SetDownTarget(ns3::IpL4Protocol::DownTargetCallback cb) [member function]
    cls.add_method('SetDownTarget', 
                   'void', 
                   [param('ns3::Callback< void, ns3::Ptr< ns3::Packet >, ns3::Ipv4Address, ns3::Ipv4Address, unsigned char, ns3::Ptr< ns3::Ipv4Route >, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'cb')], 
                   is_virtual=True)
    ## tcp-l4-protocol.h (module 'internet'): void ns3::TcpL4Protocol::SetDownTarget6(ns3::IpL4Protocol::DownTargetCallback6 cb) [member function]
    cls.add_method('SetDownTarget6', 
                   'void', 
                   [param('ns3::Callback< void, ns3::Ptr< ns3::Packet >, ns3::Ipv6Address, ns3::Ipv6Address, unsigned char, ns3::Ptr< ns3::Ipv6Route >, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'cb')], 
                   is_virtual=True)
    ## tcp-l4-protocol.h (module 'internet'): int ns3::TcpL4Protocol::GetProtocolNumber() const [member function]
    cls.add_method('GetProtocolNumber', 
                   'int', 
                   [], 
                   is_const=True, is_virtual=True)
    ## tcp-l4-protocol.h (module 'internet'): ns3::IpL4Protocol::DownTargetCallback ns3::TcpL4Protocol::GetDownTarget() const [member function]
    cls.add_method('GetDownTarget', 
                   'ns3::IpL4Protocol::DownTargetCallback', 
                   [], 
                   is_const=True, is_virtual=True)
    ## tcp-l4-protocol.h (module 'internet'): ns3::IpL4Protocol::DownTargetCallback6 ns3::TcpL4Protocol::GetDownTarget6() const [member function]
    cls.add_method('GetDownTarget6', 
                   'ns3::IpL4Protocol::DownTargetCallback6', 
                   [], 
                   is_const=True, is_virtual=True)
    ## tcp-l4-protocol.h (module 'internet'): void ns3::TcpL4Protocol::DoDispose() [member function]
    cls.add_method('DoDispose', 
                   'void', 
                   [], 
                   visibility='protected', is_virtual=True)
    ## tcp-l4-protocol.h (module 'internet'): void ns3::TcpL4Protocol::NotifyNewAggregate() [member function]
    cls.add_method('NotifyNewAggregate', 
                   'void', 
                   [], 
                   visibility='protected', is_virtual=True)
    ## tcp-l4-protocol.h (module 'internet'): ns3::IpL4Protocol::RxStatus ns3::TcpL4Protocol::PacketReceived(ns3::Ptr<ns3::Packet> packet, ns3::TcpHeader & incomingTcpHeader, ns3::Address const & source, ns3::Address const & destination) [member function]
    cls.add_method('PacketReceived', 
                   'ns3::IpL4Protocol::RxStatus', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('ns3::TcpHeader &', 'incomingTcpHeader'), param('ns3::Address const &', 'source'), param('ns3::Address const &', 'destination')], 
                   visibility='protected')
    ## tcp-l4-protocol.h (module 'internet'): void ns3::TcpL4Protocol::NoEndPointsFound(ns3::TcpHeader const & incomingHeader, ns3::Address const & incomingSAddr, ns3::Address const & incomingDAddr) [member function]
    cls.add_method('NoEndPointsFound', 
                   'void', 
                   [param('ns3::TcpHeader const &', 'incomingHeader'), param('ns3::Address const &', 'incomingSAddr'), param('ns3::Address const &', 'incomingDAddr')], 
                   visibility='protected')
    return

def register_Ns3TimeValue_methods(root_module, cls):
    ## nstime.h (module 'core'): ns3::TimeValue::TimeValue() [constructor]
    cls.add_constructor([])
    ## nstime.h (module 'core'): ns3::TimeValue::TimeValue(ns3::Time const & value) [constructor]
    cls.add_constructor([param('ns3::Time const &', 'value')])
    ## nstime.h (module 'core'): ns3::TimeValue::TimeValue(ns3::TimeValue const & arg0) [constructor]
    cls.add_constructor([param('ns3::TimeValue const &', 'arg0')])
    ## nstime.h (module 'core'): ns3::Ptr<ns3::AttributeValue> ns3::TimeValue::Copy() const [member function]
    cls.add_method('Copy', 
                   'ns3::Ptr< ns3::AttributeValue >', 
                   [], 
                   is_const=True, is_virtual=True)
    ## nstime.h (module 'core'): bool ns3::TimeValue::DeserializeFromString(std::string value, ns3::Ptr<const ns3::AttributeChecker> checker) [member function]
    cls.add_method('DeserializeFromString', 
                   'bool', 
                   [param('std::string', 'value'), param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_virtual=True)
    ## nstime.h (module 'core'): ns3::Time ns3::TimeValue::Get() const [member function]
    cls.add_method('Get', 
                   'ns3::Time', 
                   [], 
                   is_const=True)
    ## nstime.h (module 'core'): std::string ns3::TimeValue::SerializeToString(ns3::Ptr<const ns3::AttributeChecker> checker) const [member function]
    cls.add_method('SerializeToString', 
                   'std::string', 
                   [param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_const=True, is_virtual=True)
    ## nstime.h (module 'core'): void ns3::TimeValue::Set(ns3::Time const & value) [member function]
    cls.add_method('Set', 
                   'void', 
                   [param('ns3::Time const &', 'value')])
    return

def register_Ns3TypeIdChecker_methods(root_module, cls):
    ## type-id.h (module 'core'): ns3::TypeIdChecker::TypeIdChecker() [constructor]
    cls.add_constructor([])
    ## type-id.h (module 'core'): ns3::TypeIdChecker::TypeIdChecker(ns3::TypeIdChecker const & arg0) [constructor]
    cls.add_constructor([param('ns3::TypeIdChecker const &', 'arg0')])
    return

def register_Ns3TypeIdValue_methods(root_module, cls):
    ## type-id.h (module 'core'): ns3::TypeIdValue::TypeIdValue() [constructor]
    cls.add_constructor([])
    ## type-id.h (module 'core'): ns3::TypeIdValue::TypeIdValue(ns3::TypeId const & value) [constructor]
    cls.add_constructor([param('ns3::TypeId const &', 'value')])
    ## type-id.h (module 'core'): ns3::TypeIdValue::TypeIdValue(ns3::TypeIdValue const & arg0) [constructor]
    cls.add_constructor([param('ns3::TypeIdValue const &', 'arg0')])
    ## type-id.h (module 'core'): ns3::Ptr<ns3::AttributeValue> ns3::TypeIdValue::Copy() const [member function]
    cls.add_method('Copy', 
                   'ns3::Ptr< ns3::AttributeValue >', 
                   [], 
                   is_const=True, is_virtual=True)
    ## type-id.h (module 'core'): bool ns3::TypeIdValue::DeserializeFromString(std::string value, ns3::Ptr<const ns3::AttributeChecker> checker) [member function]
    cls.add_method('DeserializeFromString', 
                   'bool', 
                   [param('std::string', 'value'), param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_virtual=True)
    ## type-id.h (module 'core'): ns3::TypeId ns3::TypeIdValue::Get() const [member function]
    cls.add_method('Get', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True)
    ## type-id.h (module 'core'): std::string ns3::TypeIdValue::SerializeToString(ns3::Ptr<const ns3::AttributeChecker> checker) const [member function]
    cls.add_method('SerializeToString', 
                   'std::string', 
                   [param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_const=True, is_virtual=True)
    ## type-id.h (module 'core'): void ns3::TypeIdValue::Set(ns3::TypeId const & value) [member function]
    cls.add_method('Set', 
                   'void', 
                   [param('ns3::TypeId const &', 'value')])
    return

def register_Ns3UdpL4Protocol_methods(root_module, cls):
    ## udp-l4-protocol.h (module 'internet'): static ns3::TypeId ns3::UdpL4Protocol::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## udp-l4-protocol.h (module 'internet'): ns3::UdpL4Protocol::PROT_NUMBER [variable]
    cls.add_static_attribute('PROT_NUMBER', 'uint8_t const', is_const=True)
    ## udp-l4-protocol.h (module 'internet'): ns3::UdpL4Protocol::UdpL4Protocol() [constructor]
    cls.add_constructor([])
    ## udp-l4-protocol.h (module 'internet'): void ns3::UdpL4Protocol::SetNode(ns3::Ptr<ns3::Node> node) [member function]
    cls.add_method('SetNode', 
                   'void', 
                   [param('ns3::Ptr< ns3::Node >', 'node')])
    ## udp-l4-protocol.h (module 'internet'): int ns3::UdpL4Protocol::GetProtocolNumber() const [member function]
    cls.add_method('GetProtocolNumber', 
                   'int', 
                   [], 
                   is_const=True, is_virtual=True)
    ## udp-l4-protocol.h (module 'internet'): ns3::Ptr<ns3::Socket> ns3::UdpL4Protocol::CreateSocket() [member function]
    cls.add_method('CreateSocket', 
                   'ns3::Ptr< ns3::Socket >', 
                   [])
    ## udp-l4-protocol.h (module 'internet'): ns3::Ipv4EndPoint * ns3::UdpL4Protocol::Allocate() [member function]
    cls.add_method('Allocate', 
                   'ns3::Ipv4EndPoint *', 
                   [])
    ## udp-l4-protocol.h (module 'internet'): ns3::Ipv4EndPoint * ns3::UdpL4Protocol::Allocate(ns3::Ipv4Address address) [member function]
    cls.add_method('Allocate', 
                   'ns3::Ipv4EndPoint *', 
                   [param('ns3::Ipv4Address', 'address')])
    ## udp-l4-protocol.h (module 'internet'): ns3::Ipv4EndPoint * ns3::UdpL4Protocol::Allocate(ns3::Ptr<ns3::NetDevice> boundNetDevice, uint16_t port) [member function]
    cls.add_method('Allocate', 
                   'ns3::Ipv4EndPoint *', 
                   [param('ns3::Ptr< ns3::NetDevice >', 'boundNetDevice'), param('uint16_t', 'port')])
    ## udp-l4-protocol.h (module 'internet'): ns3::Ipv4EndPoint * ns3::UdpL4Protocol::Allocate(ns3::Ptr<ns3::NetDevice> boundNetDevice, ns3::Ipv4Address address, uint16_t port) [member function]
    cls.add_method('Allocate', 
                   'ns3::Ipv4EndPoint *', 
                   [param('ns3::Ptr< ns3::NetDevice >', 'boundNetDevice'), param('ns3::Ipv4Address', 'address'), param('uint16_t', 'port')])
    ## udp-l4-protocol.h (module 'internet'): ns3::Ipv4EndPoint * ns3::UdpL4Protocol::Allocate(ns3::Ptr<ns3::NetDevice> boundNetDevice, ns3::Ipv4Address localAddress, uint16_t localPort, ns3::Ipv4Address peerAddress, uint16_t peerPort) [member function]
    cls.add_method('Allocate', 
                   'ns3::Ipv4EndPoint *', 
                   [param('ns3::Ptr< ns3::NetDevice >', 'boundNetDevice'), param('ns3::Ipv4Address', 'localAddress'), param('uint16_t', 'localPort'), param('ns3::Ipv4Address', 'peerAddress'), param('uint16_t', 'peerPort')])
    ## udp-l4-protocol.h (module 'internet'): ns3::Ipv6EndPoint * ns3::UdpL4Protocol::Allocate6() [member function]
    cls.add_method('Allocate6', 
                   'ns3::Ipv6EndPoint *', 
                   [])
    ## udp-l4-protocol.h (module 'internet'): ns3::Ipv6EndPoint * ns3::UdpL4Protocol::Allocate6(ns3::Ipv6Address address) [member function]
    cls.add_method('Allocate6', 
                   'ns3::Ipv6EndPoint *', 
                   [param('ns3::Ipv6Address', 'address')])
    ## udp-l4-protocol.h (module 'internet'): ns3::Ipv6EndPoint * ns3::UdpL4Protocol::Allocate6(ns3::Ptr<ns3::NetDevice> boundNetDevice, uint16_t port) [member function]
    cls.add_method('Allocate6', 
                   'ns3::Ipv6EndPoint *', 
                   [param('ns3::Ptr< ns3::NetDevice >', 'boundNetDevice'), param('uint16_t', 'port')])
    ## udp-l4-protocol.h (module 'internet'): ns3::Ipv6EndPoint * ns3::UdpL4Protocol::Allocate6(ns3::Ptr<ns3::NetDevice> boundNetDevice, ns3::Ipv6Address address, uint16_t port) [member function]
    cls.add_method('Allocate6', 
                   'ns3::Ipv6EndPoint *', 
                   [param('ns3::Ptr< ns3::NetDevice >', 'boundNetDevice'), param('ns3::Ipv6Address', 'address'), param('uint16_t', 'port')])
    ## udp-l4-protocol.h (module 'internet'): ns3::Ipv6EndPoint * ns3::UdpL4Protocol::Allocate6(ns3::Ptr<ns3::NetDevice> boundNetDevice, ns3::Ipv6Address localAddress, uint16_t localPort, ns3::Ipv6Address peerAddress, uint16_t peerPort) [member function]
    cls.add_method('Allocate6', 
                   'ns3::Ipv6EndPoint *', 
                   [param('ns3::Ptr< ns3::NetDevice >', 'boundNetDevice'), param('ns3::Ipv6Address', 'localAddress'), param('uint16_t', 'localPort'), param('ns3::Ipv6Address', 'peerAddress'), param('uint16_t', 'peerPort')])
    ## udp-l4-protocol.h (module 'internet'): void ns3::UdpL4Protocol::DeAllocate(ns3::Ipv4EndPoint * endPoint) [member function]
    cls.add_method('DeAllocate', 
                   'void', 
                   [param('ns3::Ipv4EndPoint *', 'endPoint')])
    ## udp-l4-protocol.h (module 'internet'): void ns3::UdpL4Protocol::DeAllocate(ns3::Ipv6EndPoint * endPoint) [member function]
    cls.add_method('DeAllocate', 
                   'void', 
                   [param('ns3::Ipv6EndPoint *', 'endPoint')])
    ## udp-l4-protocol.h (module 'internet'): void ns3::UdpL4Protocol::Send(ns3::Ptr<ns3::Packet> packet, ns3::Ipv4Address saddr, ns3::Ipv4Address daddr, uint16_t sport, uint16_t dport) [member function]
    cls.add_method('Send', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('ns3::Ipv4Address', 'saddr'), param('ns3::Ipv4Address', 'daddr'), param('uint16_t', 'sport'), param('uint16_t', 'dport')])
    ## udp-l4-protocol.h (module 'internet'): void ns3::UdpL4Protocol::Send(ns3::Ptr<ns3::Packet> packet, ns3::Ipv4Address saddr, ns3::Ipv4Address daddr, uint16_t sport, uint16_t dport, ns3::Ptr<ns3::Ipv4Route> route) [member function]
    cls.add_method('Send', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('ns3::Ipv4Address', 'saddr'), param('ns3::Ipv4Address', 'daddr'), param('uint16_t', 'sport'), param('uint16_t', 'dport'), param('ns3::Ptr< ns3::Ipv4Route >', 'route')])
    ## udp-l4-protocol.h (module 'internet'): void ns3::UdpL4Protocol::Send(ns3::Ptr<ns3::Packet> packet, ns3::Ipv6Address saddr, ns3::Ipv6Address daddr, uint16_t sport, uint16_t dport) [member function]
    cls.add_method('Send', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('ns3::Ipv6Address', 'saddr'), param('ns3::Ipv6Address', 'daddr'), param('uint16_t', 'sport'), param('uint16_t', 'dport')])
    ## udp-l4-protocol.h (module 'internet'): void ns3::UdpL4Protocol::Send(ns3::Ptr<ns3::Packet> packet, ns3::Ipv6Address saddr, ns3::Ipv6Address daddr, uint16_t sport, uint16_t dport, ns3::Ptr<ns3::Ipv6Route> route) [member function]
    cls.add_method('Send', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('ns3::Ipv6Address', 'saddr'), param('ns3::Ipv6Address', 'daddr'), param('uint16_t', 'sport'), param('uint16_t', 'dport'), param('ns3::Ptr< ns3::Ipv6Route >', 'route')])
    ## udp-l4-protocol.h (module 'internet'): ns3::IpL4Protocol::RxStatus ns3::UdpL4Protocol::Receive(ns3::Ptr<ns3::Packet> p, ns3::Ipv4Header const & header, ns3::Ptr<ns3::Ipv4Interface> interface) [member function]
    cls.add_method('Receive', 
                   'ns3::IpL4Protocol::RxStatus', 
                   [param('ns3::Ptr< ns3::Packet >', 'p'), param('ns3::Ipv4Header const &', 'header'), param('ns3::Ptr< ns3::Ipv4Interface >', 'interface')], 
                   is_virtual=True)
    ## udp-l4-protocol.h (module 'internet'): ns3::IpL4Protocol::RxStatus ns3::UdpL4Protocol::Receive(ns3::Ptr<ns3::Packet> p, ns3::Ipv6Header const & header, ns3::Ptr<ns3::Ipv6Interface> interface) [member function]
    cls.add_method('Receive', 
                   'ns3::IpL4Protocol::RxStatus', 
                   [param('ns3::Ptr< ns3::Packet >', 'p'), param('ns3::Ipv6Header const &', 'header'), param('ns3::Ptr< ns3::Ipv6Interface >', 'interface')], 
                   is_virtual=True)
    ## udp-l4-protocol.h (module 'internet'): void ns3::UdpL4Protocol::ReceiveIcmp(ns3::Ipv4Address icmpSource, uint8_t icmpTtl, uint8_t icmpType, uint8_t icmpCode, uint32_t icmpInfo, ns3::Ipv4Address payloadSource, ns3::Ipv4Address payloadDestination, uint8_t const * payload) [member function]
    cls.add_method('ReceiveIcmp', 
                   'void', 
                   [param('ns3::Ipv4Address', 'icmpSource'), param('uint8_t', 'icmpTtl'), param('uint8_t', 'icmpType'), param('uint8_t', 'icmpCode'), param('uint32_t', 'icmpInfo'), param('ns3::Ipv4Address', 'payloadSource'), param('ns3::Ipv4Address', 'payloadDestination'), param('uint8_t const *', 'payload')], 
                   is_virtual=True)
    ## udp-l4-protocol.h (module 'internet'): void ns3::UdpL4Protocol::ReceiveIcmp(ns3::Ipv6Address icmpSource, uint8_t icmpTtl, uint8_t icmpType, uint8_t icmpCode, uint32_t icmpInfo, ns3::Ipv6Address payloadSource, ns3::Ipv6Address payloadDestination, uint8_t const * payload) [member function]
    cls.add_method('ReceiveIcmp', 
                   'void', 
                   [param('ns3::Ipv6Address', 'icmpSource'), param('uint8_t', 'icmpTtl'), param('uint8_t', 'icmpType'), param('uint8_t', 'icmpCode'), param('uint32_t', 'icmpInfo'), param('ns3::Ipv6Address', 'payloadSource'), param('ns3::Ipv6Address', 'payloadDestination'), param('uint8_t const *', 'payload')], 
                   is_virtual=True)
    ## udp-l4-protocol.h (module 'internet'): void ns3::UdpL4Protocol::SetDownTarget(ns3::IpL4Protocol::DownTargetCallback cb) [member function]
    cls.add_method('SetDownTarget', 
                   'void', 
                   [param('ns3::Callback< void, ns3::Ptr< ns3::Packet >, ns3::Ipv4Address, ns3::Ipv4Address, unsigned char, ns3::Ptr< ns3::Ipv4Route >, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'cb')], 
                   is_virtual=True)
    ## udp-l4-protocol.h (module 'internet'): void ns3::UdpL4Protocol::SetDownTarget6(ns3::IpL4Protocol::DownTargetCallback6 cb) [member function]
    cls.add_method('SetDownTarget6', 
                   'void', 
                   [param('ns3::Callback< void, ns3::Ptr< ns3::Packet >, ns3::Ipv6Address, ns3::Ipv6Address, unsigned char, ns3::Ptr< ns3::Ipv6Route >, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'cb')], 
                   is_virtual=True)
    ## udp-l4-protocol.h (module 'internet'): ns3::IpL4Protocol::DownTargetCallback ns3::UdpL4Protocol::GetDownTarget() const [member function]
    cls.add_method('GetDownTarget', 
                   'ns3::IpL4Protocol::DownTargetCallback', 
                   [], 
                   is_const=True, is_virtual=True)
    ## udp-l4-protocol.h (module 'internet'): ns3::IpL4Protocol::DownTargetCallback6 ns3::UdpL4Protocol::GetDownTarget6() const [member function]
    cls.add_method('GetDownTarget6', 
                   'ns3::IpL4Protocol::DownTargetCallback6', 
                   [], 
                   is_const=True, is_virtual=True)
    ## udp-l4-protocol.h (module 'internet'): void ns3::UdpL4Protocol::DoDispose() [member function]
    cls.add_method('DoDispose', 
                   'void', 
                   [], 
                   visibility='protected', is_virtual=True)
    ## udp-l4-protocol.h (module 'internet'): void ns3::UdpL4Protocol::NotifyNewAggregate() [member function]
    cls.add_method('NotifyNewAggregate', 
                   'void', 
                   [], 
                   visibility='protected', is_virtual=True)
    return

def register_Ns3WifiModeChecker_methods(root_module, cls):
    ## wifi-mode.h (module 'wifi'): ns3::WifiModeChecker::WifiModeChecker() [constructor]
    cls.add_constructor([])
    ## wifi-mode.h (module 'wifi'): ns3::WifiModeChecker::WifiModeChecker(ns3::WifiModeChecker const & arg0) [constructor]
    cls.add_constructor([param('ns3::WifiModeChecker const &', 'arg0')])
    return

def register_Ns3WifiModeValue_methods(root_module, cls):
    ## wifi-mode.h (module 'wifi'): ns3::WifiModeValue::WifiModeValue() [constructor]
    cls.add_constructor([])
    ## wifi-mode.h (module 'wifi'): ns3::WifiModeValue::WifiModeValue(ns3::WifiMode const & value) [constructor]
    cls.add_constructor([param('ns3::WifiMode const &', 'value')])
    ## wifi-mode.h (module 'wifi'): ns3::WifiModeValue::WifiModeValue(ns3::WifiModeValue const & arg0) [constructor]
    cls.add_constructor([param('ns3::WifiModeValue const &', 'arg0')])
    ## wifi-mode.h (module 'wifi'): ns3::Ptr<ns3::AttributeValue> ns3::WifiModeValue::Copy() const [member function]
    cls.add_method('Copy', 
                   'ns3::Ptr< ns3::AttributeValue >', 
                   [], 
                   is_const=True, is_virtual=True)
    ## wifi-mode.h (module 'wifi'): bool ns3::WifiModeValue::DeserializeFromString(std::string value, ns3::Ptr<const ns3::AttributeChecker> checker) [member function]
    cls.add_method('DeserializeFromString', 
                   'bool', 
                   [param('std::string', 'value'), param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_virtual=True)
    ## wifi-mode.h (module 'wifi'): ns3::WifiMode ns3::WifiModeValue::Get() const [member function]
    cls.add_method('Get', 
                   'ns3::WifiMode', 
                   [], 
                   is_const=True)
    ## wifi-mode.h (module 'wifi'): std::string ns3::WifiModeValue::SerializeToString(ns3::Ptr<const ns3::AttributeChecker> checker) const [member function]
    cls.add_method('SerializeToString', 
                   'std::string', 
                   [param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_const=True, is_virtual=True)
    ## wifi-mode.h (module 'wifi'): void ns3::WifiModeValue::Set(ns3::WifiMode const & value) [member function]
    cls.add_method('Set', 
                   'void', 
                   [param('ns3::WifiMode const &', 'value')])
    return

def register_Ns3AddressChecker_methods(root_module, cls):
    ## address.h (module 'network'): ns3::AddressChecker::AddressChecker() [constructor]
    cls.add_constructor([])
    ## address.h (module 'network'): ns3::AddressChecker::AddressChecker(ns3::AddressChecker const & arg0) [constructor]
    cls.add_constructor([param('ns3::AddressChecker const &', 'arg0')])
    return

def register_Ns3AddressValue_methods(root_module, cls):
    ## address.h (module 'network'): ns3::AddressValue::AddressValue() [constructor]
    cls.add_constructor([])
    ## address.h (module 'network'): ns3::AddressValue::AddressValue(ns3::Address const & value) [constructor]
    cls.add_constructor([param('ns3::Address const &', 'value')])
    ## address.h (module 'network'): ns3::AddressValue::AddressValue(ns3::AddressValue const & arg0) [constructor]
    cls.add_constructor([param('ns3::AddressValue const &', 'arg0')])
    ## address.h (module 'network'): ns3::Ptr<ns3::AttributeValue> ns3::AddressValue::Copy() const [member function]
    cls.add_method('Copy', 
                   'ns3::Ptr< ns3::AttributeValue >', 
                   [], 
                   is_const=True, is_virtual=True)
    ## address.h (module 'network'): bool ns3::AddressValue::DeserializeFromString(std::string value, ns3::Ptr<const ns3::AttributeChecker> checker) [member function]
    cls.add_method('DeserializeFromString', 
                   'bool', 
                   [param('std::string', 'value'), param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_virtual=True)
    ## address.h (module 'network'): ns3::Address ns3::AddressValue::Get() const [member function]
    cls.add_method('Get', 
                   'ns3::Address', 
                   [], 
                   is_const=True)
    ## address.h (module 'network'): std::string ns3::AddressValue::SerializeToString(ns3::Ptr<const ns3::AttributeChecker> checker) const [member function]
    cls.add_method('SerializeToString', 
                   'std::string', 
                   [param('ns3::Ptr< ns3::AttributeChecker const >', 'checker')], 
                   is_const=True, is_virtual=True)
    ## address.h (module 'network'): void ns3::AddressValue::Set(ns3::Address const & value) [member function]
    cls.add_method('Set', 
                   'void', 
                   [param('ns3::Address const &', 'value')])
    return

def register_Ns3CallbackImpl__Bool_Ns3Ptr__lt__ns3Socket__gt___Const_ns3Address___amp___Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, cls):
    ## callback.h (module 'core'): ns3::CallbackImpl<bool, ns3::Ptr<ns3::Socket>, const ns3::Address &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl() [constructor]
    cls.add_constructor([])
    ## callback.h (module 'core'): ns3::CallbackImpl<bool, ns3::Ptr<ns3::Socket>, const ns3::Address &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl(ns3::CallbackImpl<bool, ns3::Ptr<ns3::Socket>, const ns3::Address &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> const & arg0) [constructor]
    cls.add_constructor([param('ns3::CallbackImpl< bool, ns3::Ptr< ns3::Socket >, ns3::Address const &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty > const &', 'arg0')])
    ## callback.h (module 'core'): static std::string ns3::CallbackImpl<bool, ns3::Ptr<ns3::Socket>, const ns3::Address &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::DoGetTypeid() [member function]
    cls.add_method('DoGetTypeid', 
                   'std::string', 
                   [], 
                   is_static=True)
    ## callback.h (module 'core'): std::string ns3::CallbackImpl<bool, ns3::Ptr<ns3::Socket>, const ns3::Address &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::GetTypeid() const [member function]
    cls.add_method('GetTypeid', 
                   'std::string', 
                   [], 
                   is_const=True, is_virtual=True)
    ## callback.h (module 'core'): bool ns3::CallbackImpl<bool, ns3::Ptr<ns3::Socket>, const ns3::Address &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::operator()(ns3::Ptr<ns3::Socket> arg0, ns3::Address const & arg1) [member operator]
    cls.add_method('operator()', 
                   'bool', 
                   [param('ns3::Ptr< ns3::Socket >', 'arg0'), param('ns3::Address const &', 'arg1')], 
                   is_pure_virtual=True, is_virtual=True, custom_name=u'__call__')
    return

def register_Ns3CallbackImpl__Ns3ObjectBase___star___Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, cls):
    ## callback.h (module 'core'): ns3::CallbackImpl<ns3::ObjectBase *, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl() [constructor]
    cls.add_constructor([])
    ## callback.h (module 'core'): ns3::CallbackImpl<ns3::ObjectBase *, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl(ns3::CallbackImpl<ns3::ObjectBase *, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> const & arg0) [constructor]
    cls.add_constructor([param('ns3::CallbackImpl< ns3::ObjectBase *, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty > const &', 'arg0')])
    ## callback.h (module 'core'): static std::string ns3::CallbackImpl<ns3::ObjectBase *, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::DoGetTypeid() [member function]
    cls.add_method('DoGetTypeid', 
                   'std::string', 
                   [], 
                   is_static=True)
    ## callback.h (module 'core'): std::string ns3::CallbackImpl<ns3::ObjectBase *, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::GetTypeid() const [member function]
    cls.add_method('GetTypeid', 
                   'std::string', 
                   [], 
                   is_const=True, is_virtual=True)
    ## callback.h (module 'core'): ns3::ObjectBase * ns3::CallbackImpl<ns3::ObjectBase *, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::operator()() [member operator]
    cls.add_method('operator()', 
                   'ns3::ObjectBase *', 
                   [], 
                   is_pure_virtual=True, is_virtual=True, custom_name=u'__call__')
    return

def register_Ns3CallbackImpl__Void_Const_ns3Ipv4Header___amp___Ns3Ptr__lt__const_ns3Packet__gt___Ns3Ipv4L3ProtocolDropReason_Ns3Ptr__lt__ns3Ipv4__gt___Unsigned_int_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, cls):
    ## callback.h (module 'core'): ns3::CallbackImpl<void, const ns3::Ipv4Header &, ns3::Ptr<const ns3::Packet>, ns3::Ipv4L3Protocol::DropReason, ns3::Ptr<ns3::Ipv4>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl() [constructor]
    cls.add_constructor([])
    ## callback.h (module 'core'): ns3::CallbackImpl<void, const ns3::Ipv4Header &, ns3::Ptr<const ns3::Packet>, ns3::Ipv4L3Protocol::DropReason, ns3::Ptr<ns3::Ipv4>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl(ns3::CallbackImpl<void, const ns3::Ipv4Header &, ns3::Ptr<const ns3::Packet>, ns3::Ipv4L3Protocol::DropReason, ns3::Ptr<ns3::Ipv4>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty> const & arg0) [constructor]
    cls.add_constructor([param('ns3::CallbackImpl< void, ns3::Ipv4Header const &, ns3::Ptr< ns3::Packet const >, ns3::Ipv4L3Protocol::DropReason, ns3::Ptr< ns3::Ipv4 >, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty > const &', 'arg0')])
    ## callback.h (module 'core'): static std::string ns3::CallbackImpl<void, const ns3::Ipv4Header &, ns3::Ptr<const ns3::Packet>, ns3::Ipv4L3Protocol::DropReason, ns3::Ptr<ns3::Ipv4>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::DoGetTypeid() [member function]
    cls.add_method('DoGetTypeid', 
                   'std::string', 
                   [], 
                   is_static=True)
    ## callback.h (module 'core'): std::string ns3::CallbackImpl<void, const ns3::Ipv4Header &, ns3::Ptr<const ns3::Packet>, ns3::Ipv4L3Protocol::DropReason, ns3::Ptr<ns3::Ipv4>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::GetTypeid() const [member function]
    cls.add_method('GetTypeid', 
                   'std::string', 
                   [], 
                   is_const=True, is_virtual=True)
    ## callback.h (module 'core'): void ns3::CallbackImpl<void, const ns3::Ipv4Header &, ns3::Ptr<const ns3::Packet>, ns3::Ipv4L3Protocol::DropReason, ns3::Ptr<ns3::Ipv4>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::operator()(ns3::Ipv4Header const & arg0, ns3::Ptr<const ns3::Packet> arg1, ns3::Ipv4L3Protocol::DropReason arg2, ns3::Ptr<ns3::Ipv4> arg3, unsigned int arg4) [member operator]
    cls.add_method('operator()', 
                   'void', 
                   [param('ns3::Ipv4Header const &', 'arg0'), param('ns3::Ptr< ns3::Packet const >', 'arg1'), param('ns3::Ipv4L3Protocol::DropReason', 'arg2'), param('ns3::Ptr< ns3::Ipv4 >', 'arg3'), param('unsigned int', 'arg4')], 
                   is_pure_virtual=True, is_virtual=True, custom_name=u'__call__')
    return

def register_Ns3CallbackImpl__Void_Const_ns3Ipv4Header___amp___Ns3Ptr__lt__const_ns3Packet__gt___Unsigned_int_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, cls):
    ## callback.h (module 'core'): ns3::CallbackImpl<void, const ns3::Ipv4Header &, ns3::Ptr<const ns3::Packet>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl() [constructor]
    cls.add_constructor([])
    ## callback.h (module 'core'): ns3::CallbackImpl<void, const ns3::Ipv4Header &, ns3::Ptr<const ns3::Packet>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl(ns3::CallbackImpl<void, const ns3::Ipv4Header &, ns3::Ptr<const ns3::Packet>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> const & arg0) [constructor]
    cls.add_constructor([param('ns3::CallbackImpl< void, ns3::Ipv4Header const &, ns3::Ptr< ns3::Packet const >, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty > const &', 'arg0')])
    ## callback.h (module 'core'): static std::string ns3::CallbackImpl<void, const ns3::Ipv4Header &, ns3::Ptr<const ns3::Packet>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::DoGetTypeid() [member function]
    cls.add_method('DoGetTypeid', 
                   'std::string', 
                   [], 
                   is_static=True)
    ## callback.h (module 'core'): std::string ns3::CallbackImpl<void, const ns3::Ipv4Header &, ns3::Ptr<const ns3::Packet>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::GetTypeid() const [member function]
    cls.add_method('GetTypeid', 
                   'std::string', 
                   [], 
                   is_const=True, is_virtual=True)
    ## callback.h (module 'core'): void ns3::CallbackImpl<void, const ns3::Ipv4Header &, ns3::Ptr<const ns3::Packet>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::operator()(ns3::Ipv4Header const & arg0, ns3::Ptr<const ns3::Packet> arg1, unsigned int arg2) [member operator]
    cls.add_method('operator()', 
                   'void', 
                   [param('ns3::Ipv4Header const &', 'arg0'), param('ns3::Ptr< ns3::Packet const >', 'arg1'), param('unsigned int', 'arg2')], 
                   is_pure_virtual=True, is_virtual=True, custom_name=u'__call__')
    return

def register_Ns3CallbackImpl__Void_Const_ns3WifiMacHeader___amp___Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, cls):
    ## callback.h (module 'core'): ns3::CallbackImpl<void, const ns3::WifiMacHeader &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl() [constructor]
    cls.add_constructor([])
    ## callback.h (module 'core'): ns3::CallbackImpl<void, const ns3::WifiMacHeader &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl(ns3::CallbackImpl<void, const ns3::WifiMacHeader &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> const & arg0) [constructor]
    cls.add_constructor([param('ns3::CallbackImpl< void, ns3::WifiMacHeader const &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty > const &', 'arg0')])
    ## callback.h (module 'core'): static std::string ns3::CallbackImpl<void, const ns3::WifiMacHeader &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::DoGetTypeid() [member function]
    cls.add_method('DoGetTypeid', 
                   'std::string', 
                   [], 
                   is_static=True)
    ## callback.h (module 'core'): std::string ns3::CallbackImpl<void, const ns3::WifiMacHeader &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::GetTypeid() const [member function]
    cls.add_method('GetTypeid', 
                   'std::string', 
                   [], 
                   is_const=True, is_virtual=True)
    ## callback.h (module 'core'): void ns3::CallbackImpl<void, const ns3::WifiMacHeader &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::operator()(ns3::WifiMacHeader const & arg0) [member operator]
    cls.add_method('operator()', 
                   'void', 
                   [param('ns3::WifiMacHeader const &', 'arg0')], 
                   is_pure_virtual=True, is_virtual=True, custom_name=u'__call__')
    return

def register_Ns3CallbackImpl__Void_Const_ns3RushattackdsrRushattackdsrOptionSRHeader___amp___Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, cls):
    ## callback.h (module 'core'): ns3::CallbackImpl<void, const ns3::rushattackdsr::RushattackdsrOptionSRHeader &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl() [constructor]
    cls.add_constructor([])
    ## callback.h (module 'core'): ns3::CallbackImpl<void, const ns3::rushattackdsr::RushattackdsrOptionSRHeader &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl(ns3::CallbackImpl<void, const ns3::rushattackdsr::RushattackdsrOptionSRHeader &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> const & arg0) [constructor]
    cls.add_constructor([param('ns3::CallbackImpl< void, ns3::rushattackdsr::RushattackdsrOptionSRHeader const &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty > const &', 'arg0')])
    ## callback.h (module 'core'): static std::string ns3::CallbackImpl<void, const ns3::rushattackdsr::RushattackdsrOptionSRHeader &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::DoGetTypeid() [member function]
    cls.add_method('DoGetTypeid', 
                   'std::string', 
                   [], 
                   is_static=True)
    ## callback.h (module 'core'): std::string ns3::CallbackImpl<void, const ns3::rushattackdsr::RushattackdsrOptionSRHeader &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::GetTypeid() const [member function]
    cls.add_method('GetTypeid', 
                   'std::string', 
                   [], 
                   is_const=True, is_virtual=True)
    ## callback.h (module 'core'): void ns3::CallbackImpl<void, const ns3::rushattackdsr::RushattackdsrOptionSRHeader &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::operator()(ns3::rushattackdsr::RushattackdsrOptionSRHeader const & arg0) [member operator]
    cls.add_method('operator()', 
                   'void', 
                   [param('ns3::rushattackdsr::RushattackdsrOptionSRHeader const &', 'arg0')], 
                   is_pure_virtual=True, is_virtual=True, custom_name=u'__call__')
    return

def register_Ns3CallbackImpl__Void_Ns3Ipv4Address_Unsigned_char_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, cls):
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Ipv4Address, unsigned char, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl() [constructor]
    cls.add_constructor([])
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Ipv4Address, unsigned char, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl(ns3::CallbackImpl<void, ns3::Ipv4Address, unsigned char, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> const & arg0) [constructor]
    cls.add_constructor([param('ns3::CallbackImpl< void, ns3::Ipv4Address, unsigned char, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty > const &', 'arg0')])
    ## callback.h (module 'core'): static std::string ns3::CallbackImpl<void, ns3::Ipv4Address, unsigned char, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::DoGetTypeid() [member function]
    cls.add_method('DoGetTypeid', 
                   'std::string', 
                   [], 
                   is_static=True)
    ## callback.h (module 'core'): std::string ns3::CallbackImpl<void, ns3::Ipv4Address, unsigned char, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::GetTypeid() const [member function]
    cls.add_method('GetTypeid', 
                   'std::string', 
                   [], 
                   is_const=True, is_virtual=True)
    ## callback.h (module 'core'): void ns3::CallbackImpl<void, ns3::Ipv4Address, unsigned char, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::operator()(ns3::Ipv4Address arg0, unsigned char arg1) [member operator]
    cls.add_method('operator()', 
                   'void', 
                   [param('ns3::Ipv4Address', 'arg0'), param('unsigned char', 'arg1')], 
                   is_pure_virtual=True, is_virtual=True, custom_name=u'__call__')
    return

def register_Ns3CallbackImpl__Void_Ns3Mac48Address_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, cls):
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Mac48Address, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl() [constructor]
    cls.add_constructor([])
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Mac48Address, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl(ns3::CallbackImpl<void, ns3::Mac48Address, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> const & arg0) [constructor]
    cls.add_constructor([param('ns3::CallbackImpl< void, ns3::Mac48Address, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty > const &', 'arg0')])
    ## callback.h (module 'core'): static std::string ns3::CallbackImpl<void, ns3::Mac48Address, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::DoGetTypeid() [member function]
    cls.add_method('DoGetTypeid', 
                   'std::string', 
                   [], 
                   is_static=True)
    ## callback.h (module 'core'): std::string ns3::CallbackImpl<void, ns3::Mac48Address, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::GetTypeid() const [member function]
    cls.add_method('GetTypeid', 
                   'std::string', 
                   [], 
                   is_const=True, is_virtual=True)
    ## callback.h (module 'core'): void ns3::CallbackImpl<void, ns3::Mac48Address, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::operator()(ns3::Mac48Address arg0) [member operator]
    cls.add_method('operator()', 
                   'void', 
                   [param('ns3::Mac48Address', 'arg0')], 
                   is_pure_virtual=True, is_virtual=True, custom_name=u'__call__')
    return

def register_Ns3CallbackImpl__Void_Ns3Ptr__lt__const_ns3Packet__gt___Ns3Ptr__lt__ns3Ipv4__gt___Unsigned_int_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, cls):
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Ptr<const ns3::Packet>, ns3::Ptr<ns3::Ipv4>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl() [constructor]
    cls.add_constructor([])
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Ptr<const ns3::Packet>, ns3::Ptr<ns3::Ipv4>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl(ns3::CallbackImpl<void, ns3::Ptr<const ns3::Packet>, ns3::Ptr<ns3::Ipv4>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> const & arg0) [constructor]
    cls.add_constructor([param('ns3::CallbackImpl< void, ns3::Ptr< ns3::Packet const >, ns3::Ptr< ns3::Ipv4 >, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty > const &', 'arg0')])
    ## callback.h (module 'core'): static std::string ns3::CallbackImpl<void, ns3::Ptr<const ns3::Packet>, ns3::Ptr<ns3::Ipv4>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::DoGetTypeid() [member function]
    cls.add_method('DoGetTypeid', 
                   'std::string', 
                   [], 
                   is_static=True)
    ## callback.h (module 'core'): std::string ns3::CallbackImpl<void, ns3::Ptr<const ns3::Packet>, ns3::Ptr<ns3::Ipv4>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::GetTypeid() const [member function]
    cls.add_method('GetTypeid', 
                   'std::string', 
                   [], 
                   is_const=True, is_virtual=True)
    ## callback.h (module 'core'): void ns3::CallbackImpl<void, ns3::Ptr<const ns3::Packet>, ns3::Ptr<ns3::Ipv4>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::operator()(ns3::Ptr<const ns3::Packet> arg0, ns3::Ptr<ns3::Ipv4> arg1, unsigned int arg2) [member operator]
    cls.add_method('operator()', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet const >', 'arg0'), param('ns3::Ptr< ns3::Ipv4 >', 'arg1'), param('unsigned int', 'arg2')], 
                   is_pure_virtual=True, is_virtual=True, custom_name=u'__call__')
    return

def register_Ns3CallbackImpl__Void_Ns3Ptr__lt__const_ns3Packet__gt___Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, cls):
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Ptr<const ns3::Packet>, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl() [constructor]
    cls.add_constructor([])
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Ptr<const ns3::Packet>, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl(ns3::CallbackImpl<void, ns3::Ptr<const ns3::Packet>, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> const & arg0) [constructor]
    cls.add_constructor([param('ns3::CallbackImpl< void, ns3::Ptr< ns3::Packet const >, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty > const &', 'arg0')])
    ## callback.h (module 'core'): static std::string ns3::CallbackImpl<void, ns3::Ptr<const ns3::Packet>, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::DoGetTypeid() [member function]
    cls.add_method('DoGetTypeid', 
                   'std::string', 
                   [], 
                   is_static=True)
    ## callback.h (module 'core'): std::string ns3::CallbackImpl<void, ns3::Ptr<const ns3::Packet>, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::GetTypeid() const [member function]
    cls.add_method('GetTypeid', 
                   'std::string', 
                   [], 
                   is_const=True, is_virtual=True)
    ## callback.h (module 'core'): void ns3::CallbackImpl<void, ns3::Ptr<const ns3::Packet>, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::operator()(ns3::Ptr<const ns3::Packet> arg0) [member operator]
    cls.add_method('operator()', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet const >', 'arg0')], 
                   is_pure_virtual=True, is_virtual=True, custom_name=u'__call__')
    return

def register_Ns3CallbackImpl__Void_Ns3Ptr__lt__ns3NetDevice__gt___Ns3Ptr__lt__const_ns3Packet__gt___Unsigned_short_Const_ns3Address___amp___Const_ns3Address___amp___Ns3NetDevicePacketType_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, cls):
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Ptr<ns3::NetDevice>, ns3::Ptr<const ns3::Packet>, unsigned short, const ns3::Address &, const ns3::Address &, ns3::NetDevice::PacketType, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl() [constructor]
    cls.add_constructor([])
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Ptr<ns3::NetDevice>, ns3::Ptr<const ns3::Packet>, unsigned short, const ns3::Address &, const ns3::Address &, ns3::NetDevice::PacketType, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl(ns3::CallbackImpl<void, ns3::Ptr<ns3::NetDevice>, ns3::Ptr<const ns3::Packet>, unsigned short, const ns3::Address &, const ns3::Address &, ns3::NetDevice::PacketType, ns3::empty, ns3::empty, ns3::empty> const & arg0) [constructor]
    cls.add_constructor([param('ns3::CallbackImpl< void, ns3::Ptr< ns3::NetDevice >, ns3::Ptr< ns3::Packet const >, unsigned short, ns3::Address const &, ns3::Address const &, ns3::NetDevice::PacketType, ns3::empty, ns3::empty, ns3::empty > const &', 'arg0')])
    ## callback.h (module 'core'): static std::string ns3::CallbackImpl<void, ns3::Ptr<ns3::NetDevice>, ns3::Ptr<const ns3::Packet>, unsigned short, const ns3::Address &, const ns3::Address &, ns3::NetDevice::PacketType, ns3::empty, ns3::empty, ns3::empty>::DoGetTypeid() [member function]
    cls.add_method('DoGetTypeid', 
                   'std::string', 
                   [], 
                   is_static=True)
    ## callback.h (module 'core'): std::string ns3::CallbackImpl<void, ns3::Ptr<ns3::NetDevice>, ns3::Ptr<const ns3::Packet>, unsigned short, const ns3::Address &, const ns3::Address &, ns3::NetDevice::PacketType, ns3::empty, ns3::empty, ns3::empty>::GetTypeid() const [member function]
    cls.add_method('GetTypeid', 
                   'std::string', 
                   [], 
                   is_const=True, is_virtual=True)
    ## callback.h (module 'core'): void ns3::CallbackImpl<void, ns3::Ptr<ns3::NetDevice>, ns3::Ptr<const ns3::Packet>, unsigned short, const ns3::Address &, const ns3::Address &, ns3::NetDevice::PacketType, ns3::empty, ns3::empty, ns3::empty>::operator()(ns3::Ptr<ns3::NetDevice> arg0, ns3::Ptr<const ns3::Packet> arg1, short unsigned int arg2, ns3::Address const & arg3, ns3::Address const & arg4, ns3::NetDevice::PacketType arg5) [member operator]
    cls.add_method('operator()', 
                   'void', 
                   [param('ns3::Ptr< ns3::NetDevice >', 'arg0'), param('ns3::Ptr< ns3::Packet const >', 'arg1'), param('short unsigned int', 'arg2'), param('ns3::Address const &', 'arg3'), param('ns3::Address const &', 'arg4'), param('ns3::NetDevice::PacketType', 'arg5')], 
                   is_pure_virtual=True, is_virtual=True, custom_name=u'__call__')
    return

def register_Ns3CallbackImpl__Void_Ns3Ptr__lt__ns3NetDevice__gt___Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, cls):
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Ptr<ns3::NetDevice>, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl() [constructor]
    cls.add_constructor([])
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Ptr<ns3::NetDevice>, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl(ns3::CallbackImpl<void, ns3::Ptr<ns3::NetDevice>, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> const & arg0) [constructor]
    cls.add_constructor([param('ns3::CallbackImpl< void, ns3::Ptr< ns3::NetDevice >, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty > const &', 'arg0')])
    ## callback.h (module 'core'): static std::string ns3::CallbackImpl<void, ns3::Ptr<ns3::NetDevice>, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::DoGetTypeid() [member function]
    cls.add_method('DoGetTypeid', 
                   'std::string', 
                   [], 
                   is_static=True)
    ## callback.h (module 'core'): std::string ns3::CallbackImpl<void, ns3::Ptr<ns3::NetDevice>, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::GetTypeid() const [member function]
    cls.add_method('GetTypeid', 
                   'std::string', 
                   [], 
                   is_const=True, is_virtual=True)
    ## callback.h (module 'core'): void ns3::CallbackImpl<void, ns3::Ptr<ns3::NetDevice>, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::operator()(ns3::Ptr<ns3::NetDevice> arg0) [member operator]
    cls.add_method('operator()', 
                   'void', 
                   [param('ns3::Ptr< ns3::NetDevice >', 'arg0')], 
                   is_pure_virtual=True, is_virtual=True, custom_name=u'__call__')
    return

def register_Ns3CallbackImpl__Void_Ns3Ptr__lt__ns3Packet__gt___Ns3Ipv4Address_Ns3Ipv4Address_Unsigned_char_Ns3Ptr__lt__ns3Ipv4Route__gt___Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, cls):
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Ptr<ns3::Packet>, ns3::Ipv4Address, ns3::Ipv4Address, unsigned char, ns3::Ptr<ns3::Ipv4Route>, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl() [constructor]
    cls.add_constructor([])
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Ptr<ns3::Packet>, ns3::Ipv4Address, ns3::Ipv4Address, unsigned char, ns3::Ptr<ns3::Ipv4Route>, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl(ns3::CallbackImpl<void, ns3::Ptr<ns3::Packet>, ns3::Ipv4Address, ns3::Ipv4Address, unsigned char, ns3::Ptr<ns3::Ipv4Route>, ns3::empty, ns3::empty, ns3::empty, ns3::empty> const & arg0) [constructor]
    cls.add_constructor([param('ns3::CallbackImpl< void, ns3::Ptr< ns3::Packet >, ns3::Ipv4Address, ns3::Ipv4Address, unsigned char, ns3::Ptr< ns3::Ipv4Route >, ns3::empty, ns3::empty, ns3::empty, ns3::empty > const &', 'arg0')])
    ## callback.h (module 'core'): static std::string ns3::CallbackImpl<void, ns3::Ptr<ns3::Packet>, ns3::Ipv4Address, ns3::Ipv4Address, unsigned char, ns3::Ptr<ns3::Ipv4Route>, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::DoGetTypeid() [member function]
    cls.add_method('DoGetTypeid', 
                   'std::string', 
                   [], 
                   is_static=True)
    ## callback.h (module 'core'): std::string ns3::CallbackImpl<void, ns3::Ptr<ns3::Packet>, ns3::Ipv4Address, ns3::Ipv4Address, unsigned char, ns3::Ptr<ns3::Ipv4Route>, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::GetTypeid() const [member function]
    cls.add_method('GetTypeid', 
                   'std::string', 
                   [], 
                   is_const=True, is_virtual=True)
    ## callback.h (module 'core'): void ns3::CallbackImpl<void, ns3::Ptr<ns3::Packet>, ns3::Ipv4Address, ns3::Ipv4Address, unsigned char, ns3::Ptr<ns3::Ipv4Route>, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::operator()(ns3::Ptr<ns3::Packet> arg0, ns3::Ipv4Address arg1, ns3::Ipv4Address arg2, unsigned char arg3, ns3::Ptr<ns3::Ipv4Route> arg4) [member operator]
    cls.add_method('operator()', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet >', 'arg0'), param('ns3::Ipv4Address', 'arg1'), param('ns3::Ipv4Address', 'arg2'), param('unsigned char', 'arg3'), param('ns3::Ptr< ns3::Ipv4Route >', 'arg4')], 
                   is_pure_virtual=True, is_virtual=True, custom_name=u'__call__')
    return

def register_Ns3CallbackImpl__Void_Ns3Ptr__lt__ns3Socket__gt___Const_ns3Address___amp___Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, cls):
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Ptr<ns3::Socket>, const ns3::Address &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl() [constructor]
    cls.add_constructor([])
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Ptr<ns3::Socket>, const ns3::Address &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl(ns3::CallbackImpl<void, ns3::Ptr<ns3::Socket>, const ns3::Address &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> const & arg0) [constructor]
    cls.add_constructor([param('ns3::CallbackImpl< void, ns3::Ptr< ns3::Socket >, ns3::Address const &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty > const &', 'arg0')])
    ## callback.h (module 'core'): static std::string ns3::CallbackImpl<void, ns3::Ptr<ns3::Socket>, const ns3::Address &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::DoGetTypeid() [member function]
    cls.add_method('DoGetTypeid', 
                   'std::string', 
                   [], 
                   is_static=True)
    ## callback.h (module 'core'): std::string ns3::CallbackImpl<void, ns3::Ptr<ns3::Socket>, const ns3::Address &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::GetTypeid() const [member function]
    cls.add_method('GetTypeid', 
                   'std::string', 
                   [], 
                   is_const=True, is_virtual=True)
    ## callback.h (module 'core'): void ns3::CallbackImpl<void, ns3::Ptr<ns3::Socket>, const ns3::Address &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::operator()(ns3::Ptr<ns3::Socket> arg0, ns3::Address const & arg1) [member operator]
    cls.add_method('operator()', 
                   'void', 
                   [param('ns3::Ptr< ns3::Socket >', 'arg0'), param('ns3::Address const &', 'arg1')], 
                   is_pure_virtual=True, is_virtual=True, custom_name=u'__call__')
    return

def register_Ns3CallbackImpl__Void_Ns3Ptr__lt__ns3Socket__gt___Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, cls):
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Ptr<ns3::Socket>, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl() [constructor]
    cls.add_constructor([])
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Ptr<ns3::Socket>, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl(ns3::CallbackImpl<void, ns3::Ptr<ns3::Socket>, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> const & arg0) [constructor]
    cls.add_constructor([param('ns3::CallbackImpl< void, ns3::Ptr< ns3::Socket >, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty > const &', 'arg0')])
    ## callback.h (module 'core'): static std::string ns3::CallbackImpl<void, ns3::Ptr<ns3::Socket>, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::DoGetTypeid() [member function]
    cls.add_method('DoGetTypeid', 
                   'std::string', 
                   [], 
                   is_static=True)
    ## callback.h (module 'core'): std::string ns3::CallbackImpl<void, ns3::Ptr<ns3::Socket>, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::GetTypeid() const [member function]
    cls.add_method('GetTypeid', 
                   'std::string', 
                   [], 
                   is_const=True, is_virtual=True)
    ## callback.h (module 'core'): void ns3::CallbackImpl<void, ns3::Ptr<ns3::Socket>, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::operator()(ns3::Ptr<ns3::Socket> arg0) [member operator]
    cls.add_method('operator()', 
                   'void', 
                   [param('ns3::Ptr< ns3::Socket >', 'arg0')], 
                   is_pure_virtual=True, is_virtual=True, custom_name=u'__call__')
    return

def register_Ns3CallbackImpl__Void_Ns3Ptr__lt__ns3Socket__gt___Unsigned_int_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_Ns3Empty_methods(root_module, cls):
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Ptr<ns3::Socket>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl() [constructor]
    cls.add_constructor([])
    ## callback.h (module 'core'): ns3::CallbackImpl<void, ns3::Ptr<ns3::Socket>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::CallbackImpl(ns3::CallbackImpl<void, ns3::Ptr<ns3::Socket>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> const & arg0) [constructor]
    cls.add_constructor([param('ns3::CallbackImpl< void, ns3::Ptr< ns3::Socket >, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty > const &', 'arg0')])
    ## callback.h (module 'core'): static std::string ns3::CallbackImpl<void, ns3::Ptr<ns3::Socket>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::DoGetTypeid() [member function]
    cls.add_method('DoGetTypeid', 
                   'std::string', 
                   [], 
                   is_static=True)
    ## callback.h (module 'core'): std::string ns3::CallbackImpl<void, ns3::Ptr<ns3::Socket>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::GetTypeid() const [member function]
    cls.add_method('GetTypeid', 
                   'std::string', 
                   [], 
                   is_const=True, is_virtual=True)
    ## callback.h (module 'core'): void ns3::CallbackImpl<void, ns3::Ptr<ns3::Socket>, unsigned int, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty>::operator()(ns3::Ptr<ns3::Socket> arg0, unsigned int arg1) [member operator]
    cls.add_method('operator()', 
                   'void', 
                   [param('ns3::Ptr< ns3::Socket >', 'arg0'), param('unsigned int', 'arg1')], 
                   is_pure_virtual=True, is_virtual=True, custom_name=u'__call__')
    return

def register_Ns3Icmpv4L4Protocol_methods(root_module, cls):
    ## icmpv4-l4-protocol.h (module 'internet'): ns3::Icmpv4L4Protocol::Icmpv4L4Protocol(ns3::Icmpv4L4Protocol const & arg0) [constructor]
    cls.add_constructor([param('ns3::Icmpv4L4Protocol const &', 'arg0')])
    ## icmpv4-l4-protocol.h (module 'internet'): ns3::Icmpv4L4Protocol::Icmpv4L4Protocol() [constructor]
    cls.add_constructor([])
    ## icmpv4-l4-protocol.h (module 'internet'): ns3::IpL4Protocol::DownTargetCallback ns3::Icmpv4L4Protocol::GetDownTarget() const [member function]
    cls.add_method('GetDownTarget', 
                   'ns3::IpL4Protocol::DownTargetCallback', 
                   [], 
                   is_const=True, is_virtual=True)
    ## icmpv4-l4-protocol.h (module 'internet'): ns3::IpL4Protocol::DownTargetCallback6 ns3::Icmpv4L4Protocol::GetDownTarget6() const [member function]
    cls.add_method('GetDownTarget6', 
                   'ns3::IpL4Protocol::DownTargetCallback6', 
                   [], 
                   is_const=True, is_virtual=True)
    ## icmpv4-l4-protocol.h (module 'internet'): int ns3::Icmpv4L4Protocol::GetProtocolNumber() const [member function]
    cls.add_method('GetProtocolNumber', 
                   'int', 
                   [], 
                   is_const=True, is_virtual=True)
    ## icmpv4-l4-protocol.h (module 'internet'): static uint16_t ns3::Icmpv4L4Protocol::GetStaticProtocolNumber() [member function]
    cls.add_method('GetStaticProtocolNumber', 
                   'uint16_t', 
                   [], 
                   is_static=True)
    ## icmpv4-l4-protocol.h (module 'internet'): static ns3::TypeId ns3::Icmpv4L4Protocol::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## icmpv4-l4-protocol.h (module 'internet'): ns3::IpL4Protocol::RxStatus ns3::Icmpv4L4Protocol::Receive(ns3::Ptr<ns3::Packet> p, ns3::Ipv4Header const & header, ns3::Ptr<ns3::Ipv4Interface> incomingInterface) [member function]
    cls.add_method('Receive', 
                   'ns3::IpL4Protocol::RxStatus', 
                   [param('ns3::Ptr< ns3::Packet >', 'p'), param('ns3::Ipv4Header const &', 'header'), param('ns3::Ptr< ns3::Ipv4Interface >', 'incomingInterface')], 
                   is_virtual=True)
    ## icmpv4-l4-protocol.h (module 'internet'): ns3::IpL4Protocol::RxStatus ns3::Icmpv4L4Protocol::Receive(ns3::Ptr<ns3::Packet> p, ns3::Ipv6Header const & header, ns3::Ptr<ns3::Ipv6Interface> incomingInterface) [member function]
    cls.add_method('Receive', 
                   'ns3::IpL4Protocol::RxStatus', 
                   [param('ns3::Ptr< ns3::Packet >', 'p'), param('ns3::Ipv6Header const &', 'header'), param('ns3::Ptr< ns3::Ipv6Interface >', 'incomingInterface')], 
                   is_virtual=True)
    ## icmpv4-l4-protocol.h (module 'internet'): void ns3::Icmpv4L4Protocol::SendDestUnreachFragNeeded(ns3::Ipv4Header header, ns3::Ptr<const ns3::Packet> orgData, uint16_t nextHopMtu) [member function]
    cls.add_method('SendDestUnreachFragNeeded', 
                   'void', 
                   [param('ns3::Ipv4Header', 'header'), param('ns3::Ptr< ns3::Packet const >', 'orgData'), param('uint16_t', 'nextHopMtu')])
    ## icmpv4-l4-protocol.h (module 'internet'): void ns3::Icmpv4L4Protocol::SendDestUnreachPort(ns3::Ipv4Header header, ns3::Ptr<const ns3::Packet> orgData) [member function]
    cls.add_method('SendDestUnreachPort', 
                   'void', 
                   [param('ns3::Ipv4Header', 'header'), param('ns3::Ptr< ns3::Packet const >', 'orgData')])
    ## icmpv4-l4-protocol.h (module 'internet'): void ns3::Icmpv4L4Protocol::SendTimeExceededTtl(ns3::Ipv4Header header, ns3::Ptr<const ns3::Packet> orgData, bool isFragment) [member function]
    cls.add_method('SendTimeExceededTtl', 
                   'void', 
                   [param('ns3::Ipv4Header', 'header'), param('ns3::Ptr< ns3::Packet const >', 'orgData'), param('bool', 'isFragment')])
    ## icmpv4-l4-protocol.h (module 'internet'): void ns3::Icmpv4L4Protocol::SetDownTarget(ns3::IpL4Protocol::DownTargetCallback cb) [member function]
    cls.add_method('SetDownTarget', 
                   'void', 
                   [param('ns3::Callback< void, ns3::Ptr< ns3::Packet >, ns3::Ipv4Address, ns3::Ipv4Address, unsigned char, ns3::Ptr< ns3::Ipv4Route >, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'cb')], 
                   is_virtual=True)
    ## icmpv4-l4-protocol.h (module 'internet'): void ns3::Icmpv4L4Protocol::SetDownTarget6(ns3::IpL4Protocol::DownTargetCallback6 cb) [member function]
    cls.add_method('SetDownTarget6', 
                   'void', 
                   [param('ns3::Callback< void, ns3::Ptr< ns3::Packet >, ns3::Ipv6Address, ns3::Ipv6Address, unsigned char, ns3::Ptr< ns3::Ipv6Route >, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'cb')], 
                   is_virtual=True)
    ## icmpv4-l4-protocol.h (module 'internet'): void ns3::Icmpv4L4Protocol::SetNode(ns3::Ptr<ns3::Node> node) [member function]
    cls.add_method('SetNode', 
                   'void', 
                   [param('ns3::Ptr< ns3::Node >', 'node')])
    ## icmpv4-l4-protocol.h (module 'internet'): ns3::Icmpv4L4Protocol::PROT_NUMBER [variable]
    cls.add_static_attribute('PROT_NUMBER', 'uint8_t const', is_const=True)
    ## icmpv4-l4-protocol.h (module 'internet'): void ns3::Icmpv4L4Protocol::NotifyNewAggregate() [member function]
    cls.add_method('NotifyNewAggregate', 
                   'void', 
                   [], 
                   visibility='protected', is_virtual=True)
    ## icmpv4-l4-protocol.h (module 'internet'): void ns3::Icmpv4L4Protocol::DoDispose() [member function]
    cls.add_method('DoDispose', 
                   'void', 
                   [], 
                   visibility='private', is_virtual=True)
    return

def register_Ns3HashImplementation_methods(root_module, cls):
    ## hash-function.h (module 'core'): ns3::Hash::Implementation::Implementation(ns3::Hash::Implementation const & arg0) [constructor]
    cls.add_constructor([param('ns3::Hash::Implementation const &', 'arg0')])
    ## hash-function.h (module 'core'): ns3::Hash::Implementation::Implementation() [constructor]
    cls.add_constructor([])
    ## hash-function.h (module 'core'): uint32_t ns3::Hash::Implementation::GetHash32(char const * buffer, std::size_t const size) [member function]
    cls.add_method('GetHash32', 
                   'uint32_t', 
                   [param('char const *', 'buffer'), param('std::size_t const', 'size')], 
                   is_pure_virtual=True, is_virtual=True)
    ## hash-function.h (module 'core'): uint64_t ns3::Hash::Implementation::GetHash64(char const * buffer, std::size_t const size) [member function]
    cls.add_method('GetHash64', 
                   'uint64_t', 
                   [param('char const *', 'buffer'), param('std::size_t const', 'size')], 
                   is_virtual=True)
    ## hash-function.h (module 'core'): void ns3::Hash::Implementation::clear() [member function]
    cls.add_method('clear', 
                   'void', 
                   [], 
                   is_pure_virtual=True, is_virtual=True)
    return

def register_Ns3HashFunctionFnv1a_methods(root_module, cls):
    ## hash-fnv.h (module 'core'): ns3::Hash::Function::Fnv1a::Fnv1a(ns3::Hash::Function::Fnv1a const & arg0) [constructor]
    cls.add_constructor([param('ns3::Hash::Function::Fnv1a const &', 'arg0')])
    ## hash-fnv.h (module 'core'): ns3::Hash::Function::Fnv1a::Fnv1a() [constructor]
    cls.add_constructor([])
    ## hash-fnv.h (module 'core'): uint32_t ns3::Hash::Function::Fnv1a::GetHash32(char const * buffer, size_t const size) [member function]
    cls.add_method('GetHash32', 
                   'uint32_t', 
                   [param('char const *', 'buffer'), param('size_t const', 'size')], 
                   is_virtual=True)
    ## hash-fnv.h (module 'core'): uint64_t ns3::Hash::Function::Fnv1a::GetHash64(char const * buffer, size_t const size) [member function]
    cls.add_method('GetHash64', 
                   'uint64_t', 
                   [param('char const *', 'buffer'), param('size_t const', 'size')], 
                   is_virtual=True)
    ## hash-fnv.h (module 'core'): void ns3::Hash::Function::Fnv1a::clear() [member function]
    cls.add_method('clear', 
                   'void', 
                   [], 
                   is_virtual=True)
    return

def register_Ns3HashFunctionHash32_methods(root_module, cls):
    ## hash-function.h (module 'core'): ns3::Hash::Function::Hash32::Hash32(ns3::Hash::Function::Hash32 const & arg0) [constructor]
    cls.add_constructor([param('ns3::Hash::Function::Hash32 const &', 'arg0')])
    ## hash-function.h (module 'core'): ns3::Hash::Function::Hash32::Hash32(ns3::Hash::Hash32Function_ptr hp) [constructor]
    cls.add_constructor([param('ns3::Hash::Hash32Function_ptr', 'hp')])
    ## hash-function.h (module 'core'): uint32_t ns3::Hash::Function::Hash32::GetHash32(char const * buffer, std::size_t const size) [member function]
    cls.add_method('GetHash32', 
                   'uint32_t', 
                   [param('char const *', 'buffer'), param('std::size_t const', 'size')], 
                   is_virtual=True)
    ## hash-function.h (module 'core'): void ns3::Hash::Function::Hash32::clear() [member function]
    cls.add_method('clear', 
                   'void', 
                   [], 
                   is_virtual=True)
    return

def register_Ns3HashFunctionHash64_methods(root_module, cls):
    ## hash-function.h (module 'core'): ns3::Hash::Function::Hash64::Hash64(ns3::Hash::Function::Hash64 const & arg0) [constructor]
    cls.add_constructor([param('ns3::Hash::Function::Hash64 const &', 'arg0')])
    ## hash-function.h (module 'core'): ns3::Hash::Function::Hash64::Hash64(ns3::Hash::Hash64Function_ptr hp) [constructor]
    cls.add_constructor([param('ns3::Hash::Hash64Function_ptr', 'hp')])
    ## hash-function.h (module 'core'): uint32_t ns3::Hash::Function::Hash64::GetHash32(char const * buffer, std::size_t const size) [member function]
    cls.add_method('GetHash32', 
                   'uint32_t', 
                   [param('char const *', 'buffer'), param('std::size_t const', 'size')], 
                   is_virtual=True)
    ## hash-function.h (module 'core'): uint64_t ns3::Hash::Function::Hash64::GetHash64(char const * buffer, std::size_t const size) [member function]
    cls.add_method('GetHash64', 
                   'uint64_t', 
                   [param('char const *', 'buffer'), param('std::size_t const', 'size')], 
                   is_virtual=True)
    ## hash-function.h (module 'core'): void ns3::Hash::Function::Hash64::clear() [member function]
    cls.add_method('clear', 
                   'void', 
                   [], 
                   is_virtual=True)
    return

def register_Ns3HashFunctionMurmur3_methods(root_module, cls):
    ## hash-murmur3.h (module 'core'): ns3::Hash::Function::Murmur3::Murmur3(ns3::Hash::Function::Murmur3 const & arg0) [constructor]
    cls.add_constructor([param('ns3::Hash::Function::Murmur3 const &', 'arg0')])
    ## hash-murmur3.h (module 'core'): ns3::Hash::Function::Murmur3::Murmur3() [constructor]
    cls.add_constructor([])
    ## hash-murmur3.h (module 'core'): uint32_t ns3::Hash::Function::Murmur3::GetHash32(char const * buffer, std::size_t const size) [member function]
    cls.add_method('GetHash32', 
                   'uint32_t', 
                   [param('char const *', 'buffer'), param('std::size_t const', 'size')], 
                   is_virtual=True)
    ## hash-murmur3.h (module 'core'): uint64_t ns3::Hash::Function::Murmur3::GetHash64(char const * buffer, std::size_t const size) [member function]
    cls.add_method('GetHash64', 
                   'uint64_t', 
                   [param('char const *', 'buffer'), param('std::size_t const', 'size')], 
                   is_virtual=True)
    ## hash-murmur3.h (module 'core'): void ns3::Hash::Function::Murmur3::clear() [member function]
    cls.add_method('clear', 
                   'void', 
                   [], 
                   is_virtual=True)
    return

def register_Ns3RushattackdsrBlackList_methods(root_module, cls):
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): ns3::rushattackdsr::BlackList::BlackList(ns3::rushattackdsr::BlackList const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::BlackList const &', 'arg0')])
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): ns3::rushattackdsr::BlackList::BlackList(ns3::Ipv4Address ip, ns3::Time t) [constructor]
    cls.add_constructor([param('ns3::Ipv4Address', 'ip'), param('ns3::Time', 't')])
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): ns3::rushattackdsr::BlackList::m_expireTime [variable]
    cls.add_instance_attribute('m_expireTime', 'ns3::Time', is_const=False)
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): ns3::rushattackdsr::BlackList::m_linkStates [variable]
    cls.add_instance_attribute('m_linkStates', 'ns3::rushattackdsr::LinkStates', is_const=False)
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): ns3::rushattackdsr::BlackList::m_neighborAddress [variable]
    cls.add_instance_attribute('m_neighborAddress', 'ns3::Ipv4Address', is_const=False)
    return

def register_Ns3RushattackdsrRushattackdsrErrorBuffEntry_methods(root_module, cls):
    cls.add_binary_comparison_operator('==')
    ## rushattackdsr-errorbuff.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrErrorBuffEntry::RushattackdsrErrorBuffEntry(ns3::rushattackdsr::RushattackdsrErrorBuffEntry const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrErrorBuffEntry const &', 'arg0')])
    ## rushattackdsr-errorbuff.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrErrorBuffEntry::RushattackdsrErrorBuffEntry(ns3::Ptr<const ns3::Packet> pa=0, ns3::Ipv4Address d=ns3::Ipv4Address(), ns3::Ipv4Address s=ns3::Ipv4Address(), ns3::Ipv4Address n=ns3::Ipv4Address(), ns3::Time exp=ns3::Simulator::Now(), uint8_t p=0) [constructor]
    cls.add_constructor([param('ns3::Ptr< ns3::Packet const >', 'pa', default_value='0'), param('ns3::Ipv4Address', 'd', default_value='ns3::Ipv4Address()'), param('ns3::Ipv4Address', 's', default_value='ns3::Ipv4Address()'), param('ns3::Ipv4Address', 'n', default_value='ns3::Ipv4Address()'), param('ns3::Time', 'exp', default_value='ns3::Simulator::Now()'), param('uint8_t', 'p', default_value='0')])
    ## rushattackdsr-errorbuff.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrErrorBuffEntry::GetDestination() const [member function]
    cls.add_method('GetDestination', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## rushattackdsr-errorbuff.h (module 'rushattackdsr'): ns3::Time ns3::rushattackdsr::RushattackdsrErrorBuffEntry::GetExpireTime() const [member function]
    cls.add_method('GetExpireTime', 
                   'ns3::Time', 
                   [], 
                   is_const=True)
    ## rushattackdsr-errorbuff.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrErrorBuffEntry::GetNextHop() const [member function]
    cls.add_method('GetNextHop', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## rushattackdsr-errorbuff.h (module 'rushattackdsr'): ns3::Ptr<const ns3::Packet> ns3::rushattackdsr::RushattackdsrErrorBuffEntry::GetPacket() const [member function]
    cls.add_method('GetPacket', 
                   'ns3::Ptr< ns3::Packet const >', 
                   [], 
                   is_const=True)
    ## rushattackdsr-errorbuff.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrErrorBuffEntry::GetProtocol() const [member function]
    cls.add_method('GetProtocol', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-errorbuff.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrErrorBuffEntry::GetSource() const [member function]
    cls.add_method('GetSource', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## rushattackdsr-errorbuff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrErrorBuffEntry::SetDestination(ns3::Ipv4Address d) [member function]
    cls.add_method('SetDestination', 
                   'void', 
                   [param('ns3::Ipv4Address', 'd')])
    ## rushattackdsr-errorbuff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrErrorBuffEntry::SetExpireTime(ns3::Time exp) [member function]
    cls.add_method('SetExpireTime', 
                   'void', 
                   [param('ns3::Time', 'exp')])
    ## rushattackdsr-errorbuff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrErrorBuffEntry::SetNextHop(ns3::Ipv4Address n) [member function]
    cls.add_method('SetNextHop', 
                   'void', 
                   [param('ns3::Ipv4Address', 'n')])
    ## rushattackdsr-errorbuff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrErrorBuffEntry::SetPacket(ns3::Ptr<const ns3::Packet> p) [member function]
    cls.add_method('SetPacket', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet const >', 'p')])
    ## rushattackdsr-errorbuff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrErrorBuffEntry::SetProtocol(uint8_t p) [member function]
    cls.add_method('SetProtocol', 
                   'void', 
                   [param('uint8_t', 'p')])
    ## rushattackdsr-errorbuff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrErrorBuffEntry::SetSource(ns3::Ipv4Address s) [member function]
    cls.add_method('SetSource', 
                   'void', 
                   [param('ns3::Ipv4Address', 's')])
    return

def register_Ns3RushattackdsrRushattackdsrErrorBuffer_methods(root_module, cls):
    ## rushattackdsr-errorbuff.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrErrorBuffer::RushattackdsrErrorBuffer(ns3::rushattackdsr::RushattackdsrErrorBuffer const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrErrorBuffer const &', 'arg0')])
    ## rushattackdsr-errorbuff.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrErrorBuffer::RushattackdsrErrorBuffer() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-errorbuff.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrErrorBuffer::Dequeue(ns3::Ipv4Address dst, ns3::rushattackdsr::RushattackdsrErrorBuffEntry & entry) [member function]
    cls.add_method('Dequeue', 
                   'bool', 
                   [param('ns3::Ipv4Address', 'dst'), param('ns3::rushattackdsr::RushattackdsrErrorBuffEntry &', 'entry')])
    ## rushattackdsr-errorbuff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrErrorBuffer::DropPacketForErrLink(ns3::Ipv4Address source, ns3::Ipv4Address nextHop) [member function]
    cls.add_method('DropPacketForErrLink', 
                   'void', 
                   [param('ns3::Ipv4Address', 'source'), param('ns3::Ipv4Address', 'nextHop')])
    ## rushattackdsr-errorbuff.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrErrorBuffer::Enqueue(ns3::rushattackdsr::RushattackdsrErrorBuffEntry & entry) [member function]
    cls.add_method('Enqueue', 
                   'bool', 
                   [param('ns3::rushattackdsr::RushattackdsrErrorBuffEntry &', 'entry')])
    ## rushattackdsr-errorbuff.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrErrorBuffer::Find(ns3::Ipv4Address dst) [member function]
    cls.add_method('Find', 
                   'bool', 
                   [param('ns3::Ipv4Address', 'dst')])
    ## rushattackdsr-errorbuff.h (module 'rushattackdsr'): std::vector<ns3::rushattackdsr::RushattackdsrErrorBuffEntry, std::allocator<ns3::rushattackdsr::RushattackdsrErrorBuffEntry> > & ns3::rushattackdsr::RushattackdsrErrorBuffer::GetBuffer() [member function]
    cls.add_method('GetBuffer', 
                   'std::vector< ns3::rushattackdsr::RushattackdsrErrorBuffEntry > &', 
                   [])
    ## rushattackdsr-errorbuff.h (module 'rushattackdsr'): ns3::Time ns3::rushattackdsr::RushattackdsrErrorBuffer::GetErrorBufferTimeout() const [member function]
    cls.add_method('GetErrorBufferTimeout', 
                   'ns3::Time', 
                   [], 
                   is_const=True)
    ## rushattackdsr-errorbuff.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrErrorBuffer::GetMaxQueueLen() const [member function]
    cls.add_method('GetMaxQueueLen', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-errorbuff.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrErrorBuffer::GetSize() [member function]
    cls.add_method('GetSize', 
                   'uint32_t', 
                   [])
    ## rushattackdsr-errorbuff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrErrorBuffer::SetErrorBufferTimeout(ns3::Time t) [member function]
    cls.add_method('SetErrorBufferTimeout', 
                   'void', 
                   [param('ns3::Time', 't')])
    ## rushattackdsr-errorbuff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrErrorBuffer::SetMaxQueueLen(uint32_t len) [member function]
    cls.add_method('SetMaxQueueLen', 
                   'void', 
                   [param('uint32_t', 'len')])
    return

def register_Ns3RushattackdsrRushattackdsrFsHeader_methods(root_module, cls):
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrFsHeader::RushattackdsrFsHeader(ns3::rushattackdsr::RushattackdsrFsHeader const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrFsHeader const &', 'arg0')])
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrFsHeader::RushattackdsrFsHeader() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrFsHeader::Deserialize(ns3::Buffer::Iterator start) [member function]
    cls.add_method('Deserialize', 
                   'uint32_t', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_virtual=True)
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): uint16_t ns3::rushattackdsr::RushattackdsrFsHeader::GetDestId() const [member function]
    cls.add_method('GetDestId', 
                   'uint16_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): ns3::TypeId ns3::rushattackdsr::RushattackdsrFsHeader::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrFsHeader::GetMessageType() const [member function]
    cls.add_method('GetMessageType', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrFsHeader::GetNextHeader() const [member function]
    cls.add_method('GetNextHeader', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): uint16_t ns3::rushattackdsr::RushattackdsrFsHeader::GetPayloadLength() const [member function]
    cls.add_method('GetPayloadLength', 
                   'uint16_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrFsHeader::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): uint16_t ns3::rushattackdsr::RushattackdsrFsHeader::GetSourceId() const [member function]
    cls.add_method('GetSourceId', 
                   'uint16_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): static ns3::TypeId ns3::rushattackdsr::RushattackdsrFsHeader::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrFsHeader::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrFsHeader::Serialize(ns3::Buffer::Iterator start) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrFsHeader::SetDestId(uint16_t destId) [member function]
    cls.add_method('SetDestId', 
                   'void', 
                   [param('uint16_t', 'destId')])
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrFsHeader::SetMessageType(uint8_t messageType) [member function]
    cls.add_method('SetMessageType', 
                   'void', 
                   [param('uint8_t', 'messageType')])
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrFsHeader::SetNextHeader(uint8_t protocol) [member function]
    cls.add_method('SetNextHeader', 
                   'void', 
                   [param('uint8_t', 'protocol')])
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrFsHeader::SetPayloadLength(uint16_t length) [member function]
    cls.add_method('SetPayloadLength', 
                   'void', 
                   [param('uint16_t', 'length')])
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrFsHeader::SetSourceId(uint16_t sourceId) [member function]
    cls.add_method('SetSourceId', 
                   'void', 
                   [param('uint16_t', 'sourceId')])
    return

def register_Ns3RushattackdsrRushattackdsrGraReply_methods(root_module, cls):
    ## rushattackdsr-gratuitous-reply-table.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrGraReply::RushattackdsrGraReply(ns3::rushattackdsr::RushattackdsrGraReply const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrGraReply const &', 'arg0')])
    ## rushattackdsr-gratuitous-reply-table.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrGraReply::RushattackdsrGraReply() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-gratuitous-reply-table.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrGraReply::AddEntry(ns3::rushattackdsr::GraReplyEntry & graTableEntry) [member function]
    cls.add_method('AddEntry', 
                   'bool', 
                   [param('ns3::rushattackdsr::GraReplyEntry &', 'graTableEntry')])
    ## rushattackdsr-gratuitous-reply-table.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrGraReply::Clear() [member function]
    cls.add_method('Clear', 
                   'void', 
                   [])
    ## rushattackdsr-gratuitous-reply-table.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrGraReply::FindAndUpdate(ns3::Ipv4Address replyTo, ns3::Ipv4Address replyFrom, ns3::Time gratReplyHoldoff) [member function]
    cls.add_method('FindAndUpdate', 
                   'bool', 
                   [param('ns3::Ipv4Address', 'replyTo'), param('ns3::Ipv4Address', 'replyFrom'), param('ns3::Time', 'gratReplyHoldoff')])
    ## rushattackdsr-gratuitous-reply-table.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrGraReply::GetGraTableSize() const [member function]
    cls.add_method('GetGraTableSize', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-gratuitous-reply-table.h (module 'rushattackdsr'): static ns3::TypeId ns3::rushattackdsr::RushattackdsrGraReply::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## rushattackdsr-gratuitous-reply-table.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrGraReply::Purge() [member function]
    cls.add_method('Purge', 
                   'void', 
                   [])
    ## rushattackdsr-gratuitous-reply-table.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrGraReply::SetGraTableSize(uint32_t g) [member function]
    cls.add_method('SetGraTableSize', 
                   'void', 
                   [param('uint32_t', 'g')])
    return

def register_Ns3RushattackdsrRushattackdsrLinkStab_methods(root_module, cls):
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrLinkStab::RushattackdsrLinkStab(ns3::rushattackdsr::RushattackdsrLinkStab const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrLinkStab const &', 'arg0')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrLinkStab::RushattackdsrLinkStab(ns3::Time linkStab=ns3::Simulator::Now()) [constructor]
    cls.add_constructor([param('ns3::Time', 'linkStab', default_value='ns3::Simulator::Now()')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::Time ns3::rushattackdsr::RushattackdsrLinkStab::GetLinkStability() const [member function]
    cls.add_method('GetLinkStability', 
                   'ns3::Time', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrLinkStab::Print() const [member function]
    cls.add_method('Print', 
                   'void', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrLinkStab::SetLinkStability(ns3::Time linkStab) [member function]
    cls.add_method('SetLinkStability', 
                   'void', 
                   [param('ns3::Time', 'linkStab')])
    return

def register_Ns3RushattackdsrRushattackdsrMaintainBuffEntry_methods(root_module, cls):
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrMaintainBuffEntry::RushattackdsrMaintainBuffEntry(ns3::rushattackdsr::RushattackdsrMaintainBuffEntry const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrMaintainBuffEntry const &', 'arg0')])
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrMaintainBuffEntry::RushattackdsrMaintainBuffEntry(ns3::Ptr<const ns3::Packet> pa=0, ns3::Ipv4Address us=ns3::Ipv4Address(), ns3::Ipv4Address n=ns3::Ipv4Address(), ns3::Ipv4Address s=ns3::Ipv4Address(), ns3::Ipv4Address dst=ns3::Ipv4Address(), uint16_t ackId=0, uint8_t segs=0, ns3::Time exp=ns3::Simulator::Now()) [constructor]
    cls.add_constructor([param('ns3::Ptr< ns3::Packet const >', 'pa', default_value='0'), param('ns3::Ipv4Address', 'us', default_value='ns3::Ipv4Address()'), param('ns3::Ipv4Address', 'n', default_value='ns3::Ipv4Address()'), param('ns3::Ipv4Address', 's', default_value='ns3::Ipv4Address()'), param('ns3::Ipv4Address', 'dst', default_value='ns3::Ipv4Address()'), param('uint16_t', 'ackId', default_value='0'), param('uint8_t', 'segs', default_value='0'), param('ns3::Time', 'exp', default_value='ns3::Simulator::Now()')])
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): uint16_t ns3::rushattackdsr::RushattackdsrMaintainBuffEntry::GetAckId() const [member function]
    cls.add_method('GetAckId', 
                   'uint16_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrMaintainBuffEntry::GetDst() const [member function]
    cls.add_method('GetDst', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::Time ns3::rushattackdsr::RushattackdsrMaintainBuffEntry::GetExpireTime() const [member function]
    cls.add_method('GetExpireTime', 
                   'ns3::Time', 
                   [], 
                   is_const=True)
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrMaintainBuffEntry::GetNextHop() const [member function]
    cls.add_method('GetNextHop', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrMaintainBuffEntry::GetOurAdd() const [member function]
    cls.add_method('GetOurAdd', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::Ptr<const ns3::Packet> ns3::rushattackdsr::RushattackdsrMaintainBuffEntry::GetPacket() const [member function]
    cls.add_method('GetPacket', 
                   'ns3::Ptr< ns3::Packet const >', 
                   [], 
                   is_const=True)
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrMaintainBuffEntry::GetSegsLeft() const [member function]
    cls.add_method('GetSegsLeft', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrMaintainBuffEntry::GetSrc() const [member function]
    cls.add_method('GetSrc', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrMaintainBuffEntry::SetAckId(uint16_t ackId) [member function]
    cls.add_method('SetAckId', 
                   'void', 
                   [param('uint16_t', 'ackId')])
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrMaintainBuffEntry::SetDst(ns3::Ipv4Address n) [member function]
    cls.add_method('SetDst', 
                   'void', 
                   [param('ns3::Ipv4Address', 'n')])
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrMaintainBuffEntry::SetExpireTime(ns3::Time exp) [member function]
    cls.add_method('SetExpireTime', 
                   'void', 
                   [param('ns3::Time', 'exp')])
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrMaintainBuffEntry::SetNextHop(ns3::Ipv4Address n) [member function]
    cls.add_method('SetNextHop', 
                   'void', 
                   [param('ns3::Ipv4Address', 'n')])
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrMaintainBuffEntry::SetOurAdd(ns3::Ipv4Address us) [member function]
    cls.add_method('SetOurAdd', 
                   'void', 
                   [param('ns3::Ipv4Address', 'us')])
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrMaintainBuffEntry::SetPacket(ns3::Ptr<const ns3::Packet> p) [member function]
    cls.add_method('SetPacket', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet const >', 'p')])
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrMaintainBuffEntry::SetSegsLeft(uint8_t segs) [member function]
    cls.add_method('SetSegsLeft', 
                   'void', 
                   [param('uint8_t', 'segs')])
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrMaintainBuffEntry::SetSrc(ns3::Ipv4Address s) [member function]
    cls.add_method('SetSrc', 
                   'void', 
                   [param('ns3::Ipv4Address', 's')])
    return

def register_Ns3RushattackdsrRushattackdsrMaintainBuffer_methods(root_module, cls):
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrMaintainBuffer::RushattackdsrMaintainBuffer(ns3::rushattackdsr::RushattackdsrMaintainBuffer const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrMaintainBuffer const &', 'arg0')])
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrMaintainBuffer::RushattackdsrMaintainBuffer() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrMaintainBuffer::AllEqual(ns3::rushattackdsr::RushattackdsrMaintainBuffEntry & entry) [member function]
    cls.add_method('AllEqual', 
                   'bool', 
                   [param('ns3::rushattackdsr::RushattackdsrMaintainBuffEntry &', 'entry')])
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrMaintainBuffer::Dequeue(ns3::Ipv4Address dst, ns3::rushattackdsr::RushattackdsrMaintainBuffEntry & entry) [member function]
    cls.add_method('Dequeue', 
                   'bool', 
                   [param('ns3::Ipv4Address', 'dst'), param('ns3::rushattackdsr::RushattackdsrMaintainBuffEntry &', 'entry')])
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrMaintainBuffer::DropPacketWithNextHop(ns3::Ipv4Address nextHop) [member function]
    cls.add_method('DropPacketWithNextHop', 
                   'void', 
                   [param('ns3::Ipv4Address', 'nextHop')])
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrMaintainBuffer::Enqueue(ns3::rushattackdsr::RushattackdsrMaintainBuffEntry & entry) [member function]
    cls.add_method('Enqueue', 
                   'bool', 
                   [param('ns3::rushattackdsr::RushattackdsrMaintainBuffEntry &', 'entry')])
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrMaintainBuffer::Find(ns3::Ipv4Address nextHop) [member function]
    cls.add_method('Find', 
                   'bool', 
                   [param('ns3::Ipv4Address', 'nextHop')])
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::Time ns3::rushattackdsr::RushattackdsrMaintainBuffer::GetMaintainBufferTimeout() const [member function]
    cls.add_method('GetMaintainBufferTimeout', 
                   'ns3::Time', 
                   [], 
                   is_const=True)
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrMaintainBuffer::GetMaxQueueLen() const [member function]
    cls.add_method('GetMaxQueueLen', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrMaintainBuffer::GetSize() [member function]
    cls.add_method('GetSize', 
                   'uint32_t', 
                   [])
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrMaintainBuffer::LinkEqual(ns3::rushattackdsr::RushattackdsrMaintainBuffEntry & entry) [member function]
    cls.add_method('LinkEqual', 
                   'bool', 
                   [param('ns3::rushattackdsr::RushattackdsrMaintainBuffEntry &', 'entry')])
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrMaintainBuffer::NetworkEqual(ns3::rushattackdsr::RushattackdsrMaintainBuffEntry & entry) [member function]
    cls.add_method('NetworkEqual', 
                   'bool', 
                   [param('ns3::rushattackdsr::RushattackdsrMaintainBuffEntry &', 'entry')])
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrMaintainBuffer::PromiscEqual(ns3::rushattackdsr::RushattackdsrMaintainBuffEntry & entry) [member function]
    cls.add_method('PromiscEqual', 
                   'bool', 
                   [param('ns3::rushattackdsr::RushattackdsrMaintainBuffEntry &', 'entry')])
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrMaintainBuffer::SetMaintainBufferTimeout(ns3::Time t) [member function]
    cls.add_method('SetMaintainBufferTimeout', 
                   'void', 
                   [param('ns3::Time', 't')])
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrMaintainBuffer::SetMaxQueueLen(uint32_t len) [member function]
    cls.add_method('SetMaxQueueLen', 
                   'void', 
                   [param('uint32_t', 'len')])
    return

def register_Ns3RushattackdsrRushattackdsrNetworkQueue_methods(root_module, cls):
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrNetworkQueue::RushattackdsrNetworkQueue(ns3::rushattackdsr::RushattackdsrNetworkQueue const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrNetworkQueue const &', 'arg0')])
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrNetworkQueue::RushattackdsrNetworkQueue() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrNetworkQueue::RushattackdsrNetworkQueue(uint32_t maxLen, ns3::Time maxDelay) [constructor]
    cls.add_constructor([param('uint32_t', 'maxLen'), param('ns3::Time', 'maxDelay')])
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrNetworkQueue::Dequeue(ns3::rushattackdsr::RushattackdsrNetworkQueueEntry & entry) [member function]
    cls.add_method('Dequeue', 
                   'bool', 
                   [param('ns3::rushattackdsr::RushattackdsrNetworkQueueEntry &', 'entry')])
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrNetworkQueue::Enqueue(ns3::rushattackdsr::RushattackdsrNetworkQueueEntry & entry) [member function]
    cls.add_method('Enqueue', 
                   'bool', 
                   [param('ns3::rushattackdsr::RushattackdsrNetworkQueueEntry &', 'entry')])
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrNetworkQueue::Find(ns3::Ipv4Address nextHop) [member function]
    cls.add_method('Find', 
                   'bool', 
                   [param('ns3::Ipv4Address', 'nextHop')])
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrNetworkQueue::FindPacketWithNexthop(ns3::Ipv4Address nextHop, ns3::rushattackdsr::RushattackdsrNetworkQueueEntry & entry) [member function]
    cls.add_method('FindPacketWithNexthop', 
                   'bool', 
                   [param('ns3::Ipv4Address', 'nextHop'), param('ns3::rushattackdsr::RushattackdsrNetworkQueueEntry &', 'entry')])
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrNetworkQueue::Flush() [member function]
    cls.add_method('Flush', 
                   'void', 
                   [])
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): ns3::Time ns3::rushattackdsr::RushattackdsrNetworkQueue::GetMaxNetworkDelay() const [member function]
    cls.add_method('GetMaxNetworkDelay', 
                   'ns3::Time', 
                   [], 
                   is_const=True)
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrNetworkQueue::GetMaxNetworkSize() const [member function]
    cls.add_method('GetMaxNetworkSize', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): std::vector<ns3::rushattackdsr::RushattackdsrNetworkQueueEntry, std::allocator<ns3::rushattackdsr::RushattackdsrNetworkQueueEntry> > & ns3::rushattackdsr::RushattackdsrNetworkQueue::GetQueue() [member function]
    cls.add_method('GetQueue', 
                   'std::vector< ns3::rushattackdsr::RushattackdsrNetworkQueueEntry > &', 
                   [])
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrNetworkQueue::GetSize() [member function]
    cls.add_method('GetSize', 
                   'uint32_t', 
                   [])
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): static ns3::TypeId ns3::rushattackdsr::RushattackdsrNetworkQueue::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrNetworkQueue::SetMaxNetworkDelay(ns3::Time delay) [member function]
    cls.add_method('SetMaxNetworkDelay', 
                   'void', 
                   [param('ns3::Time', 'delay')])
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrNetworkQueue::SetMaxNetworkSize(uint32_t maxSize) [member function]
    cls.add_method('SetMaxNetworkSize', 
                   'void', 
                   [param('uint32_t', 'maxSize')])
    return

def register_Ns3RushattackdsrRushattackdsrNetworkQueueEntry_methods(root_module, cls):
    cls.add_binary_comparison_operator('==')
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrNetworkQueueEntry::RushattackdsrNetworkQueueEntry(ns3::rushattackdsr::RushattackdsrNetworkQueueEntry const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrNetworkQueueEntry const &', 'arg0')])
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrNetworkQueueEntry::RushattackdsrNetworkQueueEntry(ns3::Ptr<const ns3::Packet> pa=0, ns3::Ipv4Address s=ns3::Ipv4Address(), ns3::Ipv4Address n=ns3::Ipv4Address(), ns3::Time exp=ns3::Simulator::Now(), ns3::Ptr<ns3::Ipv4Route> r=0) [constructor]
    cls.add_constructor([param('ns3::Ptr< ns3::Packet const >', 'pa', default_value='0'), param('ns3::Ipv4Address', 's', default_value='ns3::Ipv4Address()'), param('ns3::Ipv4Address', 'n', default_value='ns3::Ipv4Address()'), param('ns3::Time', 'exp', default_value='ns3::Simulator::Now()'), param('ns3::Ptr< ns3::Ipv4Route >', 'r', default_value='0')])
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): ns3::Time ns3::rushattackdsr::RushattackdsrNetworkQueueEntry::GetInsertedTimeStamp() const [member function]
    cls.add_method('GetInsertedTimeStamp', 
                   'ns3::Time', 
                   [], 
                   is_const=True)
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): ns3::Ptr<ns3::Ipv4Route> ns3::rushattackdsr::RushattackdsrNetworkQueueEntry::GetIpv4Route() const [member function]
    cls.add_method('GetIpv4Route', 
                   'ns3::Ptr< ns3::Ipv4Route >', 
                   [], 
                   is_const=True)
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrNetworkQueueEntry::GetNextHopAddress() const [member function]
    cls.add_method('GetNextHopAddress', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): ns3::Ptr<const ns3::Packet> ns3::rushattackdsr::RushattackdsrNetworkQueueEntry::GetPacket() const [member function]
    cls.add_method('GetPacket', 
                   'ns3::Ptr< ns3::Packet const >', 
                   [], 
                   is_const=True)
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrNetworkQueueEntry::GetSourceAddress() const [member function]
    cls.add_method('GetSourceAddress', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrNetworkQueueEntry::SetInsertedTimeStamp(ns3::Time time) [member function]
    cls.add_method('SetInsertedTimeStamp', 
                   'void', 
                   [param('ns3::Time', 'time')])
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrNetworkQueueEntry::SetIpv4Route(ns3::Ptr<ns3::Ipv4Route> route) [member function]
    cls.add_method('SetIpv4Route', 
                   'void', 
                   [param('ns3::Ptr< ns3::Ipv4Route >', 'route')])
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrNetworkQueueEntry::SetNextHopAddress(ns3::Ipv4Address addr) [member function]
    cls.add_method('SetNextHopAddress', 
                   'void', 
                   [param('ns3::Ipv4Address', 'addr')])
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrNetworkQueueEntry::SetPacket(ns3::Ptr<const ns3::Packet> p) [member function]
    cls.add_method('SetPacket', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet const >', 'p')])
    ## rushattackdsr-network-queue.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrNetworkQueueEntry::SetSourceAddress(ns3::Ipv4Address addr) [member function]
    cls.add_method('SetSourceAddress', 
                   'void', 
                   [param('ns3::Ipv4Address', 'addr')])
    return

def register_Ns3RushattackdsrRushattackdsrNodeStab_methods(root_module, cls):
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrNodeStab::RushattackdsrNodeStab(ns3::rushattackdsr::RushattackdsrNodeStab const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrNodeStab const &', 'arg0')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrNodeStab::RushattackdsrNodeStab(ns3::Time nodeStab=ns3::Simulator::Now()) [constructor]
    cls.add_constructor([param('ns3::Time', 'nodeStab', default_value='ns3::Simulator::Now()')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::Time ns3::rushattackdsr::RushattackdsrNodeStab::GetNodeStability() const [member function]
    cls.add_method('GetNodeStability', 
                   'ns3::Time', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrNodeStab::SetNodeStability(ns3::Time nodeStab) [member function]
    cls.add_method('SetNodeStability', 
                   'void', 
                   [param('ns3::Time', 'nodeStab')])
    return

def register_Ns3RushattackdsrRushattackdsrOptionField_methods(root_module, cls):
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionField::RushattackdsrOptionField(ns3::rushattackdsr::RushattackdsrOptionField const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrOptionField const &', 'arg0')])
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionField::RushattackdsrOptionField(uint32_t optionsOffset) [constructor]
    cls.add_constructor([param('uint32_t', 'optionsOffset')])
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionField::AddRushattackdsrOption(ns3::rushattackdsr::RushattackdsrOptionHeader const & option) [member function]
    cls.add_method('AddRushattackdsrOption', 
                   'void', 
                   [param('ns3::rushattackdsr::RushattackdsrOptionHeader const &', 'option')])
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrOptionField::Deserialize(ns3::Buffer::Iterator start, uint32_t length) [member function]
    cls.add_method('Deserialize', 
                   'uint32_t', 
                   [param('ns3::Buffer::Iterator', 'start'), param('uint32_t', 'length')])
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): ns3::Buffer ns3::rushattackdsr::RushattackdsrOptionField::GetRushattackdsrOptionBuffer() [member function]
    cls.add_method('GetRushattackdsrOptionBuffer', 
                   'ns3::Buffer', 
                   [])
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrOptionField::GetRushattackdsrOptionsOffset() [member function]
    cls.add_method('GetRushattackdsrOptionsOffset', 
                   'uint32_t', 
                   [])
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrOptionField::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionField::Serialize(ns3::Buffer::Iterator start) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_const=True)
    return

def register_Ns3RushattackdsrRushattackdsrOptionHeader_methods(root_module, cls):
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionHeader::RushattackdsrOptionHeader(ns3::rushattackdsr::RushattackdsrOptionHeader const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrOptionHeader const &', 'arg0')])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionHeader::RushattackdsrOptionHeader() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrOptionHeader::Deserialize(ns3::Buffer::Iterator start) [member function]
    cls.add_method('Deserialize', 
                   'uint32_t', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionHeader::Alignment ns3::rushattackdsr::RushattackdsrOptionHeader::GetAlignment() const [member function]
    cls.add_method('GetAlignment', 
                   'ns3::rushattackdsr::RushattackdsrOptionHeader::Alignment', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionHeader::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrOptionHeader::GetLength() const [member function]
    cls.add_method('GetLength', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrOptionHeader::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrOptionHeader::GetType() const [member function]
    cls.add_method('GetType', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): static ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionHeader::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionHeader::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionHeader::Serialize(ns3::Buffer::Iterator start) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionHeader::SetLength(uint8_t length) [member function]
    cls.add_method('SetLength', 
                   'void', 
                   [param('uint8_t', 'length')])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionHeader::SetType(uint8_t type) [member function]
    cls.add_method('SetType', 
                   'void', 
                   [param('uint8_t', 'type')])
    return

def register_Ns3RushattackdsrRushattackdsrOptionHeaderAlignment_methods(root_module, cls):
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionHeader::Alignment::Alignment() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionHeader::Alignment::Alignment(ns3::rushattackdsr::RushattackdsrOptionHeader::Alignment const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrOptionHeader::Alignment const &', 'arg0')])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionHeader::Alignment::factor [variable]
    cls.add_instance_attribute('factor', 'uint8_t', is_const=False)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionHeader::Alignment::offset [variable]
    cls.add_instance_attribute('offset', 'uint8_t', is_const=False)
    return

def register_Ns3RushattackdsrRushattackdsrOptionPad1Header_methods(root_module, cls):
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionPad1Header::RushattackdsrOptionPad1Header(ns3::rushattackdsr::RushattackdsrOptionPad1Header const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrOptionPad1Header const &', 'arg0')])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionPad1Header::RushattackdsrOptionPad1Header() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrOptionPad1Header::Deserialize(ns3::Buffer::Iterator start) [member function]
    cls.add_method('Deserialize', 
                   'uint32_t', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionPad1Header::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrOptionPad1Header::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): static ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionPad1Header::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionPad1Header::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionPad1Header::Serialize(ns3::Buffer::Iterator start) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_const=True, is_virtual=True)
    return

def register_Ns3RushattackdsrRushattackdsrOptionPadnHeader_methods(root_module, cls):
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionPadnHeader::RushattackdsrOptionPadnHeader(ns3::rushattackdsr::RushattackdsrOptionPadnHeader const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrOptionPadnHeader const &', 'arg0')])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionPadnHeader::RushattackdsrOptionPadnHeader(uint32_t pad=2) [constructor]
    cls.add_constructor([param('uint32_t', 'pad', default_value='2')])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrOptionPadnHeader::Deserialize(ns3::Buffer::Iterator start) [member function]
    cls.add_method('Deserialize', 
                   'uint32_t', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionPadnHeader::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrOptionPadnHeader::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): static ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionPadnHeader::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionPadnHeader::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionPadnHeader::Serialize(ns3::Buffer::Iterator start) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_const=True, is_virtual=True)
    return

def register_Ns3RushattackdsrRushattackdsrOptionRerrHeader_methods(root_module, cls):
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionRerrHeader::RushattackdsrOptionRerrHeader(ns3::rushattackdsr::RushattackdsrOptionRerrHeader const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrOptionRerrHeader const &', 'arg0')])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionRerrHeader::RushattackdsrOptionRerrHeader() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrOptionRerrHeader::Deserialize(ns3::Buffer::Iterator start) [member function]
    cls.add_method('Deserialize', 
                   'uint32_t', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionHeader::Alignment ns3::rushattackdsr::RushattackdsrOptionRerrHeader::GetAlignment() const [member function]
    cls.add_method('GetAlignment', 
                   'ns3::rushattackdsr::RushattackdsrOptionHeader::Alignment', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrOptionRerrHeader::GetErrorDst() const [member function]
    cls.add_method('GetErrorDst', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrOptionRerrHeader::GetErrorSrc() const [member function]
    cls.add_method('GetErrorSrc', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrOptionRerrHeader::GetErrorType() const [member function]
    cls.add_method('GetErrorType', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionRerrHeader::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrOptionRerrHeader::GetSalvage() const [member function]
    cls.add_method('GetSalvage', 
                   'uint8_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrOptionRerrHeader::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): static ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionRerrHeader::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRerrHeader::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRerrHeader::Serialize(ns3::Buffer::Iterator start) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRerrHeader::SetErrorDst(ns3::Ipv4Address errorDstAddress) [member function]
    cls.add_method('SetErrorDst', 
                   'void', 
                   [param('ns3::Ipv4Address', 'errorDstAddress')], 
                   is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRerrHeader::SetErrorSrc(ns3::Ipv4Address errorSrcAddress) [member function]
    cls.add_method('SetErrorSrc', 
                   'void', 
                   [param('ns3::Ipv4Address', 'errorSrcAddress')], 
                   is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRerrHeader::SetErrorType(uint8_t errorType) [member function]
    cls.add_method('SetErrorType', 
                   'void', 
                   [param('uint8_t', 'errorType')])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRerrHeader::SetSalvage(uint8_t salvage) [member function]
    cls.add_method('SetSalvage', 
                   'void', 
                   [param('uint8_t', 'salvage')], 
                   is_virtual=True)
    return

def register_Ns3RushattackdsrRushattackdsrOptionRerrUnreachHeader_methods(root_module, cls):
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionRerrUnreachHeader::RushattackdsrOptionRerrUnreachHeader(ns3::rushattackdsr::RushattackdsrOptionRerrUnreachHeader const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrOptionRerrUnreachHeader const &', 'arg0')])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionRerrUnreachHeader::RushattackdsrOptionRerrUnreachHeader() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrOptionRerrUnreachHeader::Deserialize(ns3::Buffer::Iterator start) [member function]
    cls.add_method('Deserialize', 
                   'uint32_t', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionHeader::Alignment ns3::rushattackdsr::RushattackdsrOptionRerrUnreachHeader::GetAlignment() const [member function]
    cls.add_method('GetAlignment', 
                   'ns3::rushattackdsr::RushattackdsrOptionHeader::Alignment', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrOptionRerrUnreachHeader::GetErrorDst() const [member function]
    cls.add_method('GetErrorDst', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrOptionRerrUnreachHeader::GetErrorSrc() const [member function]
    cls.add_method('GetErrorSrc', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionRerrUnreachHeader::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrOptionRerrUnreachHeader::GetOriginalDst() const [member function]
    cls.add_method('GetOriginalDst', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrOptionRerrUnreachHeader::GetSalvage() const [member function]
    cls.add_method('GetSalvage', 
                   'uint8_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrOptionRerrUnreachHeader::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): static ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionRerrUnreachHeader::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrOptionRerrUnreachHeader::GetUnreachNode() const [member function]
    cls.add_method('GetUnreachNode', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRerrUnreachHeader::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRerrUnreachHeader::Serialize(ns3::Buffer::Iterator start) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRerrUnreachHeader::SetErrorDst(ns3::Ipv4Address errorDstAddress) [member function]
    cls.add_method('SetErrorDst', 
                   'void', 
                   [param('ns3::Ipv4Address', 'errorDstAddress')], 
                   is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRerrUnreachHeader::SetErrorSrc(ns3::Ipv4Address errorSrcAddress) [member function]
    cls.add_method('SetErrorSrc', 
                   'void', 
                   [param('ns3::Ipv4Address', 'errorSrcAddress')], 
                   is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRerrUnreachHeader::SetOriginalDst(ns3::Ipv4Address originalDst) [member function]
    cls.add_method('SetOriginalDst', 
                   'void', 
                   [param('ns3::Ipv4Address', 'originalDst')])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRerrUnreachHeader::SetSalvage(uint8_t salvage) [member function]
    cls.add_method('SetSalvage', 
                   'void', 
                   [param('uint8_t', 'salvage')], 
                   is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRerrUnreachHeader::SetUnreachNode(ns3::Ipv4Address unreachNode) [member function]
    cls.add_method('SetUnreachNode', 
                   'void', 
                   [param('ns3::Ipv4Address', 'unreachNode')])
    return

def register_Ns3RushattackdsrRushattackdsrOptionRerrUnsupportHeader_methods(root_module, cls):
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionRerrUnsupportHeader::RushattackdsrOptionRerrUnsupportHeader(ns3::rushattackdsr::RushattackdsrOptionRerrUnsupportHeader const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrOptionRerrUnsupportHeader const &', 'arg0')])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionRerrUnsupportHeader::RushattackdsrOptionRerrUnsupportHeader() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrOptionRerrUnsupportHeader::Deserialize(ns3::Buffer::Iterator start) [member function]
    cls.add_method('Deserialize', 
                   'uint32_t', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionHeader::Alignment ns3::rushattackdsr::RushattackdsrOptionRerrUnsupportHeader::GetAlignment() const [member function]
    cls.add_method('GetAlignment', 
                   'ns3::rushattackdsr::RushattackdsrOptionHeader::Alignment', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrOptionRerrUnsupportHeader::GetErrorDst() const [member function]
    cls.add_method('GetErrorDst', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrOptionRerrUnsupportHeader::GetErrorSrc() const [member function]
    cls.add_method('GetErrorSrc', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionRerrUnsupportHeader::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrOptionRerrUnsupportHeader::GetSalvage() const [member function]
    cls.add_method('GetSalvage', 
                   'uint8_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrOptionRerrUnsupportHeader::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): static ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionRerrUnsupportHeader::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint16_t ns3::rushattackdsr::RushattackdsrOptionRerrUnsupportHeader::GetUnsupported() const [member function]
    cls.add_method('GetUnsupported', 
                   'uint16_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRerrUnsupportHeader::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRerrUnsupportHeader::Serialize(ns3::Buffer::Iterator start) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRerrUnsupportHeader::SetErrorDst(ns3::Ipv4Address errorDstAddress) [member function]
    cls.add_method('SetErrorDst', 
                   'void', 
                   [param('ns3::Ipv4Address', 'errorDstAddress')], 
                   is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRerrUnsupportHeader::SetErrorSrc(ns3::Ipv4Address errorSrcAddress) [member function]
    cls.add_method('SetErrorSrc', 
                   'void', 
                   [param('ns3::Ipv4Address', 'errorSrcAddress')], 
                   is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRerrUnsupportHeader::SetSalvage(uint8_t salvage) [member function]
    cls.add_method('SetSalvage', 
                   'void', 
                   [param('uint8_t', 'salvage')], 
                   is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRerrUnsupportHeader::SetUnsupported(uint16_t optionType) [member function]
    cls.add_method('SetUnsupported', 
                   'void', 
                   [param('uint16_t', 'optionType')])
    return

def register_Ns3RushattackdsrRushattackdsrOptionRrepHeader_methods(root_module, cls):
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionRrepHeader::RushattackdsrOptionRrepHeader(ns3::rushattackdsr::RushattackdsrOptionRrepHeader const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrOptionRrepHeader const &', 'arg0')])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionRrepHeader::RushattackdsrOptionRrepHeader() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrOptionRrepHeader::Deserialize(ns3::Buffer::Iterator start) [member function]
    cls.add_method('Deserialize', 
                   'uint32_t', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionHeader::Alignment ns3::rushattackdsr::RushattackdsrOptionRrepHeader::GetAlignment() const [member function]
    cls.add_method('GetAlignment', 
                   'ns3::rushattackdsr::RushattackdsrOptionHeader::Alignment', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionRrepHeader::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrOptionRrepHeader::GetNodeAddress(uint8_t index) const [member function]
    cls.add_method('GetNodeAddress', 
                   'ns3::Ipv4Address', 
                   [param('uint8_t', 'index')], 
                   is_const=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): std::vector<ns3::Ipv4Address, std::allocator<ns3::Ipv4Address> > ns3::rushattackdsr::RushattackdsrOptionRrepHeader::GetNodesAddress() const [member function]
    cls.add_method('GetNodesAddress', 
                   'std::vector< ns3::Ipv4Address >', 
                   [], 
                   is_const=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrOptionRrepHeader::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrOptionRrepHeader::GetTargetAddress(std::vector<ns3::Ipv4Address, std::allocator<ns3::Ipv4Address> > ipv4Address) const [member function]
    cls.add_method('GetTargetAddress', 
                   'ns3::Ipv4Address', 
                   [param('std::vector< ns3::Ipv4Address >', 'ipv4Address')], 
                   is_const=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): static ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionRrepHeader::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRrepHeader::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRrepHeader::Serialize(ns3::Buffer::Iterator start) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRrepHeader::SetNodeAddress(uint8_t index, ns3::Ipv4Address addr) [member function]
    cls.add_method('SetNodeAddress', 
                   'void', 
                   [param('uint8_t', 'index'), param('ns3::Ipv4Address', 'addr')])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRrepHeader::SetNodesAddress(std::vector<ns3::Ipv4Address, std::allocator<ns3::Ipv4Address> > ipv4Address) [member function]
    cls.add_method('SetNodesAddress', 
                   'void', 
                   [param('std::vector< ns3::Ipv4Address >', 'ipv4Address')])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRrepHeader::SetNumberAddress(uint8_t n) [member function]
    cls.add_method('SetNumberAddress', 
                   'void', 
                   [param('uint8_t', 'n')])
    return

def register_Ns3RushattackdsrRushattackdsrOptionRreqHeader_methods(root_module, cls):
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionRreqHeader::RushattackdsrOptionRreqHeader(ns3::rushattackdsr::RushattackdsrOptionRreqHeader const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrOptionRreqHeader const &', 'arg0')])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionRreqHeader::RushattackdsrOptionRreqHeader() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRreqHeader::AddNodeAddress(ns3::Ipv4Address ipv4) [member function]
    cls.add_method('AddNodeAddress', 
                   'void', 
                   [param('ns3::Ipv4Address', 'ipv4')])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrOptionRreqHeader::Deserialize(ns3::Buffer::Iterator start) [member function]
    cls.add_method('Deserialize', 
                   'uint32_t', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionHeader::Alignment ns3::rushattackdsr::RushattackdsrOptionRreqHeader::GetAlignment() const [member function]
    cls.add_method('GetAlignment', 
                   'ns3::rushattackdsr::RushattackdsrOptionHeader::Alignment', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint16_t ns3::rushattackdsr::RushattackdsrOptionRreqHeader::GetId() const [member function]
    cls.add_method('GetId', 
                   'uint16_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionRreqHeader::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrOptionRreqHeader::GetNodeAddress(uint8_t index) const [member function]
    cls.add_method('GetNodeAddress', 
                   'ns3::Ipv4Address', 
                   [param('uint8_t', 'index')], 
                   is_const=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): std::vector<ns3::Ipv4Address, std::allocator<ns3::Ipv4Address> > ns3::rushattackdsr::RushattackdsrOptionRreqHeader::GetNodesAddresses() const [member function]
    cls.add_method('GetNodesAddresses', 
                   'std::vector< ns3::Ipv4Address >', 
                   [], 
                   is_const=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrOptionRreqHeader::GetNodesNumber() const [member function]
    cls.add_method('GetNodesNumber', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrOptionRreqHeader::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrOptionRreqHeader::GetTarget() [member function]
    cls.add_method('GetTarget', 
                   'ns3::Ipv4Address', 
                   [])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): static ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionRreqHeader::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRreqHeader::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRreqHeader::Serialize(ns3::Buffer::Iterator start) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRreqHeader::SetId(uint16_t identification) [member function]
    cls.add_method('SetId', 
                   'void', 
                   [param('uint16_t', 'identification')])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRreqHeader::SetNodeAddress(uint8_t index, ns3::Ipv4Address addr) [member function]
    cls.add_method('SetNodeAddress', 
                   'void', 
                   [param('uint8_t', 'index'), param('ns3::Ipv4Address', 'addr')])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRreqHeader::SetNodesAddress(std::vector<ns3::Ipv4Address, std::allocator<ns3::Ipv4Address> > ipv4Address) [member function]
    cls.add_method('SetNodesAddress', 
                   'void', 
                   [param('std::vector< ns3::Ipv4Address >', 'ipv4Address')])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRreqHeader::SetNumberAddress(uint8_t n) [member function]
    cls.add_method('SetNumberAddress', 
                   'void', 
                   [param('uint8_t', 'n')])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionRreqHeader::SetTarget(ns3::Ipv4Address target) [member function]
    cls.add_method('SetTarget', 
                   'void', 
                   [param('ns3::Ipv4Address', 'target')])
    return

def register_Ns3RushattackdsrRushattackdsrOptionSRHeader_methods(root_module, cls):
    cls.add_output_stream_operator()
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionSRHeader::RushattackdsrOptionSRHeader(ns3::rushattackdsr::RushattackdsrOptionSRHeader const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrOptionSRHeader const &', 'arg0')])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionSRHeader::RushattackdsrOptionSRHeader() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrOptionSRHeader::Deserialize(ns3::Buffer::Iterator start) [member function]
    cls.add_method('Deserialize', 
                   'uint32_t', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionHeader::Alignment ns3::rushattackdsr::RushattackdsrOptionSRHeader::GetAlignment() const [member function]
    cls.add_method('GetAlignment', 
                   'ns3::rushattackdsr::RushattackdsrOptionHeader::Alignment', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionSRHeader::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrOptionSRHeader::GetNodeAddress(uint8_t index) const [member function]
    cls.add_method('GetNodeAddress', 
                   'ns3::Ipv4Address', 
                   [param('uint8_t', 'index')], 
                   is_const=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrOptionSRHeader::GetNodeListSize() const [member function]
    cls.add_method('GetNodeListSize', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): std::vector<ns3::Ipv4Address, std::allocator<ns3::Ipv4Address> > ns3::rushattackdsr::RushattackdsrOptionSRHeader::GetNodesAddress() const [member function]
    cls.add_method('GetNodesAddress', 
                   'std::vector< ns3::Ipv4Address >', 
                   [], 
                   is_const=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrOptionSRHeader::GetSalvage() const [member function]
    cls.add_method('GetSalvage', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrOptionSRHeader::GetSegmentsLeft() const [member function]
    cls.add_method('GetSegmentsLeft', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrOptionSRHeader::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): static ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionSRHeader::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionSRHeader::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionSRHeader::Serialize(ns3::Buffer::Iterator start) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionSRHeader::SetNodeAddress(uint8_t index, ns3::Ipv4Address addr) [member function]
    cls.add_method('SetNodeAddress', 
                   'void', 
                   [param('uint8_t', 'index'), param('ns3::Ipv4Address', 'addr')])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionSRHeader::SetNodesAddress(std::vector<ns3::Ipv4Address, std::allocator<ns3::Ipv4Address> > ipv4Address) [member function]
    cls.add_method('SetNodesAddress', 
                   'void', 
                   [param('std::vector< ns3::Ipv4Address >', 'ipv4Address')])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionSRHeader::SetNumberAddress(uint8_t n) [member function]
    cls.add_method('SetNumberAddress', 
                   'void', 
                   [param('uint8_t', 'n')])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionSRHeader::SetSalvage(uint8_t salvage) [member function]
    cls.add_method('SetSalvage', 
                   'void', 
                   [param('uint8_t', 'salvage')])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionSRHeader::SetSegmentsLeft(uint8_t segmentsLeft) [member function]
    cls.add_method('SetSegmentsLeft', 
                   'void', 
                   [param('uint8_t', 'segmentsLeft')])
    return

def register_Ns3RushattackdsrRushattackdsrOptions_methods(root_module, cls):
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptions::RushattackdsrOptions(ns3::rushattackdsr::RushattackdsrOptions const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrOptions const &', 'arg0')])
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptions::RushattackdsrOptions() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-options.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrOptions::CheckDuplicates(ns3::Ipv4Address ipv4Address, std::vector<ns3::Ipv4Address, std::allocator<ns3::Ipv4Address> > & vec) [member function]
    cls.add_method('CheckDuplicates', 
                   'bool', 
                   [param('ns3::Ipv4Address', 'ipv4Address'), param('std::vector< ns3::Ipv4Address > &', 'vec')])
    ## rushattackdsr-options.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrOptions::ContainAddressAfter(ns3::Ipv4Address ipv4Address, ns3::Ipv4Address destAddress, std::vector<ns3::Ipv4Address, std::allocator<ns3::Ipv4Address> > & nodeList) [member function]
    cls.add_method('ContainAddressAfter', 
                   'bool', 
                   [param('ns3::Ipv4Address', 'ipv4Address'), param('ns3::Ipv4Address', 'destAddress'), param('std::vector< ns3::Ipv4Address > &', 'nodeList')])
    ## rushattackdsr-options.h (module 'rushattackdsr'): std::vector<ns3::Ipv4Address, std::allocator<ns3::Ipv4Address> > ns3::rushattackdsr::RushattackdsrOptions::CutRoute(ns3::Ipv4Address ipv4Address, std::vector<ns3::Ipv4Address, std::allocator<ns3::Ipv4Address> > & nodeList) [member function]
    cls.add_method('CutRoute', 
                   'std::vector< ns3::Ipv4Address >', 
                   [param('ns3::Ipv4Address', 'ipv4Address'), param('std::vector< ns3::Ipv4Address > &', 'nodeList')])
    ## rushattackdsr-options.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrOptions::GetIDfromIP(ns3::Ipv4Address address) [member function]
    cls.add_method('GetIDfromIP', 
                   'uint32_t', 
                   [param('ns3::Ipv4Address', 'address')])
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::Ptr<ns3::Node> ns3::rushattackdsr::RushattackdsrOptions::GetNode() const [member function]
    cls.add_method('GetNode', 
                   'ns3::Ptr< ns3::Node >', 
                   [], 
                   is_const=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::Ptr<ns3::Node> ns3::rushattackdsr::RushattackdsrOptions::GetNodeWithAddress(ns3::Ipv4Address ipv4Address) [member function]
    cls.add_method('GetNodeWithAddress', 
                   'ns3::Ptr< ns3::Node >', 
                   [param('ns3::Ipv4Address', 'ipv4Address')])
    ## rushattackdsr-options.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrOptions::GetOptionNumber() const [member function]
    cls.add_method('GetOptionNumber', 
                   'uint8_t', 
                   [], 
                   is_pure_virtual=True, is_const=True, is_virtual=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): static ns3::TypeId ns3::rushattackdsr::RushattackdsrOptions::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrOptions::IfDuplicates(std::vector<ns3::Ipv4Address, std::allocator<ns3::Ipv4Address> > & vec, std::vector<ns3::Ipv4Address, std::allocator<ns3::Ipv4Address> > & vec2) [member function]
    cls.add_method('IfDuplicates', 
                   'bool', 
                   [param('std::vector< ns3::Ipv4Address > &', 'vec'), param('std::vector< ns3::Ipv4Address > &', 'vec2')])
    ## rushattackdsr-options.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptions::PrintVector(std::vector<ns3::Ipv4Address, std::allocator<ns3::Ipv4Address> > & vec) [member function]
    cls.add_method('PrintVector', 
                   'void', 
                   [param('std::vector< ns3::Ipv4Address > &', 'vec')])
    ## rushattackdsr-options.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrOptions::Process(ns3::Ptr<ns3::Packet> packet, ns3::Ptr<ns3::Packet> rushattackdsrP, ns3::Ipv4Address ipv4Address, ns3::Ipv4Address source, ns3::Ipv4Header const & ipv4Header, uint8_t protocol, bool & isPromisc, ns3::Ipv4Address promiscSource) [member function]
    cls.add_method('Process', 
                   'uint8_t', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('ns3::Ptr< ns3::Packet >', 'rushattackdsrP'), param('ns3::Ipv4Address', 'ipv4Address'), param('ns3::Ipv4Address', 'source'), param('ns3::Ipv4Header const &', 'ipv4Header'), param('uint8_t', 'protocol'), param('bool &', 'isPromisc'), param('ns3::Ipv4Address', 'promiscSource')], 
                   is_pure_virtual=True, is_virtual=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptions::RemoveDuplicates(std::vector<ns3::Ipv4Address, std::allocator<ns3::Ipv4Address> > & vec) [member function]
    cls.add_method('RemoveDuplicates', 
                   'void', 
                   [param('std::vector< ns3::Ipv4Address > &', 'vec')])
    ## rushattackdsr-options.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrOptions::ReverseRoutes(std::vector<ns3::Ipv4Address, std::allocator<ns3::Ipv4Address> > & vec) [member function]
    cls.add_method('ReverseRoutes', 
                   'bool', 
                   [param('std::vector< ns3::Ipv4Address > &', 'vec')])
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrOptions::ReverseSearchNextHop(ns3::Ipv4Address ipv4Address, std::vector<ns3::Ipv4Address, std::allocator<ns3::Ipv4Address> > & vec) [member function]
    cls.add_method('ReverseSearchNextHop', 
                   'ns3::Ipv4Address', 
                   [param('ns3::Ipv4Address', 'ipv4Address'), param('std::vector< ns3::Ipv4Address > &', 'vec')])
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrOptions::ReverseSearchNextTwoHop(ns3::Ipv4Address ipv4Address, std::vector<ns3::Ipv4Address, std::allocator<ns3::Ipv4Address> > & vec) [member function]
    cls.add_method('ReverseSearchNextTwoHop', 
                   'ns3::Ipv4Address', 
                   [param('ns3::Ipv4Address', 'ipv4Address'), param('std::vector< ns3::Ipv4Address > &', 'vec')])
    ## rushattackdsr-options.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptions::ScheduleReply(ns3::Ptr<ns3::Packet> & packet, std::vector<ns3::Ipv4Address, std::allocator<ns3::Ipv4Address> > & nodeList, ns3::Ipv4Address & source, ns3::Ipv4Address & destination) [member function]
    cls.add_method('ScheduleReply', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet > &', 'packet'), param('std::vector< ns3::Ipv4Address > &', 'nodeList'), param('ns3::Ipv4Address &', 'source'), param('ns3::Ipv4Address &', 'destination')])
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrOptions::SearchNextHop(ns3::Ipv4Address ipv4Address, std::vector<ns3::Ipv4Address, std::allocator<ns3::Ipv4Address> > & vec) [member function]
    cls.add_method('SearchNextHop', 
                   'ns3::Ipv4Address', 
                   [param('ns3::Ipv4Address', 'ipv4Address'), param('std::vector< ns3::Ipv4Address > &', 'vec')])
    ## rushattackdsr-options.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptions::SetNode(ns3::Ptr<ns3::Node> node) [member function]
    cls.add_method('SetNode', 
                   'void', 
                   [param('ns3::Ptr< ns3::Node >', 'node')])
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::Ptr<ns3::Ipv4Route> ns3::rushattackdsr::RushattackdsrOptions::SetRoute(ns3::Ipv4Address nextHop, ns3::Ipv4Address srcAddress) [member function]
    cls.add_method('SetRoute', 
                   'ns3::Ptr< ns3::Ipv4Route >', 
                   [param('ns3::Ipv4Address', 'nextHop'), param('ns3::Ipv4Address', 'srcAddress')], 
                   is_virtual=True)
    return

def register_Ns3RushattackdsrRushattackdsrPassiveBuffEntry_methods(root_module, cls):
    cls.add_binary_comparison_operator('==')
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrPassiveBuffEntry::RushattackdsrPassiveBuffEntry(ns3::rushattackdsr::RushattackdsrPassiveBuffEntry const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrPassiveBuffEntry const &', 'arg0')])
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrPassiveBuffEntry::RushattackdsrPassiveBuffEntry(ns3::Ptr<const ns3::Packet> pa=0, ns3::Ipv4Address d=ns3::Ipv4Address(), ns3::Ipv4Address s=ns3::Ipv4Address(), ns3::Ipv4Address n=ns3::Ipv4Address(), uint16_t i=0, uint16_t f=0, uint8_t seg=0, ns3::Time exp=ns3::Simulator::Now(), uint8_t p=0) [constructor]
    cls.add_constructor([param('ns3::Ptr< ns3::Packet const >', 'pa', default_value='0'), param('ns3::Ipv4Address', 'd', default_value='ns3::Ipv4Address()'), param('ns3::Ipv4Address', 's', default_value='ns3::Ipv4Address()'), param('ns3::Ipv4Address', 'n', default_value='ns3::Ipv4Address()'), param('uint16_t', 'i', default_value='0'), param('uint16_t', 'f', default_value='0'), param('uint8_t', 'seg', default_value='0'), param('ns3::Time', 'exp', default_value='ns3::Simulator::Now()'), param('uint8_t', 'p', default_value='0')])
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrPassiveBuffEntry::GetDestination() const [member function]
    cls.add_method('GetDestination', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): ns3::Time ns3::rushattackdsr::RushattackdsrPassiveBuffEntry::GetExpireTime() const [member function]
    cls.add_method('GetExpireTime', 
                   'ns3::Time', 
                   [], 
                   is_const=True)
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): uint16_t ns3::rushattackdsr::RushattackdsrPassiveBuffEntry::GetFragmentOffset() const [member function]
    cls.add_method('GetFragmentOffset', 
                   'uint16_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): uint16_t ns3::rushattackdsr::RushattackdsrPassiveBuffEntry::GetIdentification() const [member function]
    cls.add_method('GetIdentification', 
                   'uint16_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrPassiveBuffEntry::GetNextHop() const [member function]
    cls.add_method('GetNextHop', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): ns3::Ptr<const ns3::Packet> ns3::rushattackdsr::RushattackdsrPassiveBuffEntry::GetPacket() const [member function]
    cls.add_method('GetPacket', 
                   'ns3::Ptr< ns3::Packet const >', 
                   [], 
                   is_const=True)
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrPassiveBuffEntry::GetProtocol() const [member function]
    cls.add_method('GetProtocol', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrPassiveBuffEntry::GetSegsLeft() const [member function]
    cls.add_method('GetSegsLeft', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrPassiveBuffEntry::GetSource() const [member function]
    cls.add_method('GetSource', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrPassiveBuffEntry::SetDestination(ns3::Ipv4Address d) [member function]
    cls.add_method('SetDestination', 
                   'void', 
                   [param('ns3::Ipv4Address', 'd')])
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrPassiveBuffEntry::SetExpireTime(ns3::Time exp) [member function]
    cls.add_method('SetExpireTime', 
                   'void', 
                   [param('ns3::Time', 'exp')])
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrPassiveBuffEntry::SetFragmentOffset(uint16_t f) [member function]
    cls.add_method('SetFragmentOffset', 
                   'void', 
                   [param('uint16_t', 'f')])
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrPassiveBuffEntry::SetIdentification(uint16_t i) [member function]
    cls.add_method('SetIdentification', 
                   'void', 
                   [param('uint16_t', 'i')])
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrPassiveBuffEntry::SetNextHop(ns3::Ipv4Address n) [member function]
    cls.add_method('SetNextHop', 
                   'void', 
                   [param('ns3::Ipv4Address', 'n')])
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrPassiveBuffEntry::SetPacket(ns3::Ptr<const ns3::Packet> p) [member function]
    cls.add_method('SetPacket', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet const >', 'p')])
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrPassiveBuffEntry::SetProtocol(uint8_t p) [member function]
    cls.add_method('SetProtocol', 
                   'void', 
                   [param('uint8_t', 'p')])
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrPassiveBuffEntry::SetSegsLeft(uint8_t seg) [member function]
    cls.add_method('SetSegsLeft', 
                   'void', 
                   [param('uint8_t', 'seg')])
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrPassiveBuffEntry::SetSource(ns3::Ipv4Address s) [member function]
    cls.add_method('SetSource', 
                   'void', 
                   [param('ns3::Ipv4Address', 's')])
    return

def register_Ns3RushattackdsrRushattackdsrPassiveBuffer_methods(root_module, cls):
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrPassiveBuffer::RushattackdsrPassiveBuffer(ns3::rushattackdsr::RushattackdsrPassiveBuffer const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrPassiveBuffer const &', 'arg0')])
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrPassiveBuffer::RushattackdsrPassiveBuffer() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrPassiveBuffer::AllEqual(ns3::rushattackdsr::RushattackdsrPassiveBuffEntry & entry) [member function]
    cls.add_method('AllEqual', 
                   'bool', 
                   [param('ns3::rushattackdsr::RushattackdsrPassiveBuffEntry &', 'entry')])
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrPassiveBuffer::Dequeue(ns3::Ipv4Address dst, ns3::rushattackdsr::RushattackdsrPassiveBuffEntry & entry) [member function]
    cls.add_method('Dequeue', 
                   'bool', 
                   [param('ns3::Ipv4Address', 'dst'), param('ns3::rushattackdsr::RushattackdsrPassiveBuffEntry &', 'entry')])
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrPassiveBuffer::Enqueue(ns3::rushattackdsr::RushattackdsrPassiveBuffEntry & entry) [member function]
    cls.add_method('Enqueue', 
                   'bool', 
                   [param('ns3::rushattackdsr::RushattackdsrPassiveBuffEntry &', 'entry')])
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrPassiveBuffer::Find(ns3::Ipv4Address dst) [member function]
    cls.add_method('Find', 
                   'bool', 
                   [param('ns3::Ipv4Address', 'dst')])
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrPassiveBuffer::GetMaxQueueLen() const [member function]
    cls.add_method('GetMaxQueueLen', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): ns3::Time ns3::rushattackdsr::RushattackdsrPassiveBuffer::GetPassiveBufferTimeout() const [member function]
    cls.add_method('GetPassiveBufferTimeout', 
                   'ns3::Time', 
                   [], 
                   is_const=True)
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrPassiveBuffer::GetSize() [member function]
    cls.add_method('GetSize', 
                   'uint32_t', 
                   [])
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): static ns3::TypeId ns3::rushattackdsr::RushattackdsrPassiveBuffer::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrPassiveBuffer::SetMaxQueueLen(uint32_t len) [member function]
    cls.add_method('SetMaxQueueLen', 
                   'void', 
                   [param('uint32_t', 'len')])
    ## rushattackdsr-passive-buff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrPassiveBuffer::SetPassiveBufferTimeout(ns3::Time t) [member function]
    cls.add_method('SetPassiveBufferTimeout', 
                   'void', 
                   [param('ns3::Time', 't')])
    return

def register_Ns3RushattackdsrRushattackdsrReceivedRreqEntry_methods(root_module, cls):
    cls.add_binary_comparison_operator('==')
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrReceivedRreqEntry::RushattackdsrReceivedRreqEntry(ns3::rushattackdsr::RushattackdsrReceivedRreqEntry const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrReceivedRreqEntry const &', 'arg0')])
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrReceivedRreqEntry::RushattackdsrReceivedRreqEntry(ns3::Ipv4Address d=ns3::Ipv4Address(), uint16_t i=0) [constructor]
    cls.add_constructor([param('ns3::Ipv4Address', 'd', default_value='ns3::Ipv4Address()'), param('uint16_t', 'i', default_value='0')])
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrReceivedRreqEntry::GetDestination() const [member function]
    cls.add_method('GetDestination', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): ns3::Time ns3::rushattackdsr::RushattackdsrReceivedRreqEntry::GetExpireTime() const [member function]
    cls.add_method('GetExpireTime', 
                   'ns3::Time', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): uint16_t ns3::rushattackdsr::RushattackdsrReceivedRreqEntry::GetIdentification() const [member function]
    cls.add_method('GetIdentification', 
                   'uint16_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrReceivedRreqEntry::GetSource() const [member function]
    cls.add_method('GetSource', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrReceivedRreqEntry::SetDestination(ns3::Ipv4Address d) [member function]
    cls.add_method('SetDestination', 
                   'void', 
                   [param('ns3::Ipv4Address', 'd')])
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrReceivedRreqEntry::SetExpireTime(ns3::Time exp) [member function]
    cls.add_method('SetExpireTime', 
                   'void', 
                   [param('ns3::Time', 'exp')])
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrReceivedRreqEntry::SetIdentification(uint16_t i) [member function]
    cls.add_method('SetIdentification', 
                   'void', 
                   [param('uint16_t', 'i')])
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrReceivedRreqEntry::SetSource(ns3::Ipv4Address s) [member function]
    cls.add_method('SetSource', 
                   'void', 
                   [param('ns3::Ipv4Address', 's')])
    return

def register_Ns3RushattackdsrRushattackdsrRouteCache_methods(root_module, cls):
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRouteCache::RushattackdsrRouteCache(ns3::rushattackdsr::RushattackdsrRouteCache const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrRouteCache const &', 'arg0')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRouteCache::RushattackdsrRouteCache() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::AddArpCache(ns3::Ptr<ns3::ArpCache> arg0) [member function]
    cls.add_method('AddArpCache', 
                   'void', 
                   [param('ns3::Ptr< ns3::ArpCache >', 'arg0')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::AddNeighbor(std::vector<ns3::Ipv4Address, std::allocator<ns3::Ipv4Address> > nodeList, ns3::Ipv4Address ownAddress, ns3::Time expire) [member function]
    cls.add_method('AddNeighbor', 
                   'void', 
                   [param('std::vector< ns3::Ipv4Address >', 'nodeList'), param('ns3::Ipv4Address', 'ownAddress'), param('ns3::Time', 'expire')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrRouteCache::AddRoute(ns3::rushattackdsr::RushattackdsrRouteCacheEntry & rt) [member function]
    cls.add_method('AddRoute', 
                   'bool', 
                   [param('ns3::rushattackdsr::RushattackdsrRouteCacheEntry &', 'rt')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrRouteCache::AddRoute_Link(ns3::rushattackdsr::RushattackdsrRouteCacheEntry::IP_VECTOR nodelist, ns3::Ipv4Address node) [member function]
    cls.add_method('AddRoute_Link', 
                   'bool', 
                   [param('std::vector< ns3::Ipv4Address >', 'nodelist'), param('ns3::Ipv4Address', 'node')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): uint16_t ns3::rushattackdsr::RushattackdsrRouteCache::CheckUniqueAckId(ns3::Ipv4Address nextHop) [member function]
    cls.add_method('CheckUniqueAckId', 
                   'uint16_t', 
                   [param('ns3::Ipv4Address', 'nextHop')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::Clear() [member function]
    cls.add_method('Clear', 
                   'void', 
                   [])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::ClearMac() [member function]
    cls.add_method('ClearMac', 
                   'void', 
                   [])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::DelArpCache(ns3::Ptr<ns3::ArpCache> arg0) [member function]
    cls.add_method('DelArpCache', 
                   'void', 
                   [param('ns3::Ptr< ns3::ArpCache >', 'arg0')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::DeleteAllRoutesIncludeLink(ns3::Ipv4Address errorSrc, ns3::Ipv4Address unreachNode, ns3::Ipv4Address node) [member function]
    cls.add_method('DeleteAllRoutesIncludeLink', 
                   'void', 
                   [param('ns3::Ipv4Address', 'errorSrc'), param('ns3::Ipv4Address', 'unreachNode'), param('ns3::Ipv4Address', 'node')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrRouteCache::DeleteRoute(ns3::Ipv4Address dst) [member function]
    cls.add_method('DeleteRoute', 
                   'bool', 
                   [param('ns3::Ipv4Address', 'dst')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrRouteCache::FindSameRoute(ns3::rushattackdsr::RushattackdsrRouteCacheEntry & rt, std::list<ns3::rushattackdsr::RushattackdsrRouteCacheEntry, std::allocator<ns3::rushattackdsr::RushattackdsrRouteCacheEntry> > & rtVector) [member function]
    cls.add_method('FindSameRoute', 
                   'bool', 
                   [param('ns3::rushattackdsr::RushattackdsrRouteCacheEntry &', 'rt'), param('std::list< ns3::rushattackdsr::RushattackdsrRouteCacheEntry > &', 'rtVector')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): uint16_t ns3::rushattackdsr::RushattackdsrRouteCache::GetAckSize() [member function]
    cls.add_method('GetAckSize', 
                   'uint16_t', 
                   [])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::Time ns3::rushattackdsr::RushattackdsrRouteCache::GetBadLinkLifetime() const [member function]
    cls.add_method('GetBadLinkLifetime', 
                   'ns3::Time', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::Time ns3::rushattackdsr::RushattackdsrRouteCache::GetCacheTimeout() const [member function]
    cls.add_method('GetCacheTimeout', 
                   'ns3::Time', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::Callback<void, ns3::Ipv4Address, unsigned char, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> ns3::rushattackdsr::RushattackdsrRouteCache::GetCallback() const [member function]
    cls.add_method('GetCallback', 
                   'ns3::Callback< void, ns3::Ipv4Address, unsigned char, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::Time ns3::rushattackdsr::RushattackdsrRouteCache::GetExpireTime(ns3::Ipv4Address addr) [member function]
    cls.add_method('GetExpireTime', 
                   'ns3::Time', 
                   [param('ns3::Ipv4Address', 'addr')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::Time ns3::rushattackdsr::RushattackdsrRouteCache::GetInitStability() const [member function]
    cls.add_method('GetInitStability', 
                   'ns3::Time', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrRouteCache::GetMaxCacheLen() const [member function]
    cls.add_method('GetMaxCacheLen', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrRouteCache::GetMaxEntriesEachDst() const [member function]
    cls.add_method('GetMaxEntriesEachDst', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::Time ns3::rushattackdsr::RushattackdsrRouteCache::GetMinLifeTime() const [member function]
    cls.add_method('GetMinLifeTime', 
                   'ns3::Time', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): uint64_t ns3::rushattackdsr::RushattackdsrRouteCache::GetStabilityDecrFactor() const [member function]
    cls.add_method('GetStabilityDecrFactor', 
                   'uint64_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): uint64_t ns3::rushattackdsr::RushattackdsrRouteCache::GetStabilityIncrFactor() const [member function]
    cls.add_method('GetStabilityIncrFactor', 
                   'uint64_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrRouteCache::GetSubRoute() const [member function]
    cls.add_method('GetSubRoute', 
                   'bool', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::Callback<void, const ns3::WifiMacHeader &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> ns3::rushattackdsr::RushattackdsrRouteCache::GetTxErrorCallback() const [member function]
    cls.add_method('GetTxErrorCallback', 
                   'ns3::Callback< void, ns3::WifiMacHeader const &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): static ns3::TypeId ns3::rushattackdsr::RushattackdsrRouteCache::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::Time ns3::rushattackdsr::RushattackdsrRouteCache::GetUseExtends() const [member function]
    cls.add_method('GetUseExtends', 
                   'ns3::Time', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrRouteCache::IsLinkCache() [member function]
    cls.add_method('IsLinkCache', 
                   'bool', 
                   [])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrRouteCache::IsNeighbor(ns3::Ipv4Address addr) [member function]
    cls.add_method('IsNeighbor', 
                   'bool', 
                   [param('ns3::Ipv4Address', 'addr')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::Mac48Address ns3::rushattackdsr::RushattackdsrRouteCache::LookupMacAddress(ns3::Ipv4Address addr) [member function]
    cls.add_method('LookupMacAddress', 
                   'ns3::Mac48Address', 
                   [param('ns3::Ipv4Address', 'addr')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrRouteCache::LookupRoute(ns3::Ipv4Address id, ns3::rushattackdsr::RushattackdsrRouteCacheEntry & rt) [member function]
    cls.add_method('LookupRoute', 
                   'bool', 
                   [param('ns3::Ipv4Address', 'id'), param('ns3::rushattackdsr::RushattackdsrRouteCacheEntry &', 'rt')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::Print(std::ostream & os) [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::PrintRouteVector(std::list<ns3::rushattackdsr::RushattackdsrRouteCacheEntry, std::allocator<ns3::rushattackdsr::RushattackdsrRouteCacheEntry> > route) [member function]
    cls.add_method('PrintRouteVector', 
                   'void', 
                   [param('std::list< ns3::rushattackdsr::RushattackdsrRouteCacheEntry >', 'route')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::PrintVector(std::vector<ns3::Ipv4Address, std::allocator<ns3::Ipv4Address> > & vec) [member function]
    cls.add_method('PrintVector', 
                   'void', 
                   [param('std::vector< ns3::Ipv4Address > &', 'vec')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::ProcessTxError(ns3::WifiMacHeader const & hdr) [member function]
    cls.add_method('ProcessTxError', 
                   'void', 
                   [param('ns3::WifiMacHeader const &', 'hdr')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::Purge() [member function]
    cls.add_method('Purge', 
                   'void', 
                   [])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::PurgeLinkNode() [member function]
    cls.add_method('PurgeLinkNode', 
                   'void', 
                   [])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::PurgeMac() [member function]
    cls.add_method('PurgeMac', 
                   'void', 
                   [])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::RebuildBestRouteTable(ns3::Ipv4Address source) [member function]
    cls.add_method('RebuildBestRouteTable', 
                   'void', 
                   [param('ns3::Ipv4Address', 'source')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::RemoveLastEntry(std::list<ns3::rushattackdsr::RushattackdsrRouteCacheEntry, std::allocator<ns3::rushattackdsr::RushattackdsrRouteCacheEntry> > & rtVector) [member function]
    cls.add_method('RemoveLastEntry', 
                   'void', 
                   [param('std::list< ns3::rushattackdsr::RushattackdsrRouteCacheEntry > &', 'rtVector')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::ScheduleTimer() [member function]
    cls.add_method('ScheduleTimer', 
                   'void', 
                   [])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::SetBadLinkLifetime(ns3::Time t) [member function]
    cls.add_method('SetBadLinkLifetime', 
                   'void', 
                   [param('ns3::Time', 't')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::SetCacheTimeout(ns3::Time t) [member function]
    cls.add_method('SetCacheTimeout', 
                   'void', 
                   [param('ns3::Time', 't')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::SetCacheType(std::string type) [member function]
    cls.add_method('SetCacheType', 
                   'void', 
                   [param('std::string', 'type')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::SetCallback(ns3::Callback<void, ns3::Ipv4Address, unsigned char, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty> cb) [member function]
    cls.add_method('SetCallback', 
                   'void', 
                   [param('ns3::Callback< void, ns3::Ipv4Address, unsigned char, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'cb')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::SetInitStability(ns3::Time initStability) [member function]
    cls.add_method('SetInitStability', 
                   'void', 
                   [param('ns3::Time', 'initStability')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::SetMaxCacheLen(uint32_t len) [member function]
    cls.add_method('SetMaxCacheLen', 
                   'void', 
                   [param('uint32_t', 'len')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::SetMaxEntriesEachDst(uint32_t entries) [member function]
    cls.add_method('SetMaxEntriesEachDst', 
                   'void', 
                   [param('uint32_t', 'entries')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::SetMinLifeTime(ns3::Time minLifeTime) [member function]
    cls.add_method('SetMinLifeTime', 
                   'void', 
                   [param('ns3::Time', 'minLifeTime')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::SetStabilityDecrFactor(uint64_t decrFactor) [member function]
    cls.add_method('SetStabilityDecrFactor', 
                   'void', 
                   [param('uint64_t', 'decrFactor')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::SetStabilityIncrFactor(uint64_t incrFactor) [member function]
    cls.add_method('SetStabilityIncrFactor', 
                   'void', 
                   [param('uint64_t', 'incrFactor')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::SetSubRoute(bool subRoute) [member function]
    cls.add_method('SetSubRoute', 
                   'void', 
                   [param('bool', 'subRoute')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::SetUseExtends(ns3::Time useExtends) [member function]
    cls.add_method('SetUseExtends', 
                   'void', 
                   [param('ns3::Time', 'useExtends')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::UpdateNeighbor(std::vector<ns3::Ipv4Address, std::allocator<ns3::Ipv4Address> > nodeList, ns3::Time expire) [member function]
    cls.add_method('UpdateNeighbor', 
                   'void', 
                   [param('std::vector< ns3::Ipv4Address >', 'nodeList'), param('ns3::Time', 'expire')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::UpdateNetGraph() [member function]
    cls.add_method('UpdateNetGraph', 
                   'void', 
                   [])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrRouteCache::UpdateRouteEntry(ns3::Ipv4Address dst) [member function]
    cls.add_method('UpdateRouteEntry', 
                   'bool', 
                   [param('ns3::Ipv4Address', 'dst')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCache::UseExtends(ns3::rushattackdsr::RushattackdsrRouteCacheEntry::IP_VECTOR rt) [member function]
    cls.add_method('UseExtends', 
                   'void', 
                   [param('std::vector< ns3::Ipv4Address >', 'rt')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRouteCache::m_arp [variable]
    cls.add_instance_attribute('m_arp', 'std::vector< ns3::Ptr< ns3::ArpCache > >', is_const=False)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRouteCache::m_delay [variable]
    cls.add_instance_attribute('m_delay', 'ns3::Time', is_const=False)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRouteCache::m_handleLinkFailure [variable]
    cls.add_instance_attribute('m_handleLinkFailure', 'ns3::Callback< void, ns3::Ipv4Address, unsigned char, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', is_const=False)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRouteCache::m_nb [variable]
    cls.add_instance_attribute('m_nb', 'std::vector< ns3::rushattackdsr::RushattackdsrRouteCache::Neighbor >', is_const=False)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRouteCache::m_ntimer [variable]
    cls.add_instance_attribute('m_ntimer', 'ns3::Timer', is_const=False)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRouteCache::m_txErrorCallback [variable]
    cls.add_instance_attribute('m_txErrorCallback', 'ns3::Callback< void, ns3::WifiMacHeader const &, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', is_const=False)
    return

def register_Ns3RushattackdsrRushattackdsrRouteCacheNeighbor_methods(root_module, cls):
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRouteCache::Neighbor::Neighbor(ns3::rushattackdsr::RushattackdsrRouteCache::Neighbor const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrRouteCache::Neighbor const &', 'arg0')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRouteCache::Neighbor::Neighbor(ns3::Ipv4Address ip, ns3::Mac48Address mac, ns3::Time t) [constructor]
    cls.add_constructor([param('ns3::Ipv4Address', 'ip'), param('ns3::Mac48Address', 'mac'), param('ns3::Time', 't')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRouteCache::Neighbor::Neighbor() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRouteCache::Neighbor::close [variable]
    cls.add_instance_attribute('close', 'bool', is_const=False)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRouteCache::Neighbor::m_expireTime [variable]
    cls.add_instance_attribute('m_expireTime', 'ns3::Time', is_const=False)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRouteCache::Neighbor::m_hardwareAddress [variable]
    cls.add_instance_attribute('m_hardwareAddress', 'ns3::Mac48Address', is_const=False)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRouteCache::Neighbor::m_neighborAddress [variable]
    cls.add_instance_attribute('m_neighborAddress', 'ns3::Ipv4Address', is_const=False)
    return

def register_Ns3RushattackdsrRushattackdsrRouteCacheEntry_methods(root_module, cls):
    cls.add_binary_comparison_operator('==')
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRouteCacheEntry::RushattackdsrRouteCacheEntry(ns3::rushattackdsr::RushattackdsrRouteCacheEntry const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrRouteCacheEntry const &', 'arg0')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRouteCacheEntry::RushattackdsrRouteCacheEntry(ns3::rushattackdsr::RushattackdsrRouteCacheEntry::IP_VECTOR const & ip=::ns3::rushattackdsr::RushattackdsrRouteCacheEntry::IP_VECTOR( ), ns3::Ipv4Address dst=ns3::Ipv4Address(), ns3::Time exp=ns3::Simulator::Now()) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrRouteCacheEntry::IP_VECTOR const &', 'ip', default_value='::ns3::rushattackdsr::RushattackdsrRouteCacheEntry::IP_VECTOR( )'), param('ns3::Ipv4Address', 'dst', default_value='ns3::Ipv4Address()'), param('ns3::Time', 'exp', default_value='ns3::Simulator::Now()')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::Time ns3::rushattackdsr::RushattackdsrRouteCacheEntry::GetBlacklistTimeout() const [member function]
    cls.add_method('GetBlacklistTimeout', 
                   'ns3::Time', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrRouteCacheEntry::GetDestination() const [member function]
    cls.add_method('GetDestination', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::Time ns3::rushattackdsr::RushattackdsrRouteCacheEntry::GetExpireTime() const [member function]
    cls.add_method('GetExpireTime', 
                   'ns3::Time', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRouteCacheEntry::IP_VECTOR ns3::rushattackdsr::RushattackdsrRouteCacheEntry::GetVector() const [member function]
    cls.add_method('GetVector', 
                   'ns3::rushattackdsr::RushattackdsrRouteCacheEntry::IP_VECTOR', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCacheEntry::Invalidate(ns3::Time badLinkLifetime) [member function]
    cls.add_method('Invalidate', 
                   'void', 
                   [param('ns3::Time', 'badLinkLifetime')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrRouteCacheEntry::IsUnidirectional() const [member function]
    cls.add_method('IsUnidirectional', 
                   'bool', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCacheEntry::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCacheEntry::SetBlacklistTimeout(ns3::Time t) [member function]
    cls.add_method('SetBlacklistTimeout', 
                   'void', 
                   [param('ns3::Time', 't')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCacheEntry::SetDestination(ns3::Ipv4Address d) [member function]
    cls.add_method('SetDestination', 
                   'void', 
                   [param('ns3::Ipv4Address', 'd')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCacheEntry::SetExpireTime(ns3::Time exp) [member function]
    cls.add_method('SetExpireTime', 
                   'void', 
                   [param('ns3::Time', 'exp')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCacheEntry::SetUnidirectional(bool u) [member function]
    cls.add_method('SetUnidirectional', 
                   'void', 
                   [param('bool', 'u')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouteCacheEntry::SetVector(ns3::rushattackdsr::RushattackdsrRouteCacheEntry::IP_VECTOR v) [member function]
    cls.add_method('SetVector', 
                   'void', 
                   [param('std::vector< ns3::Ipv4Address >', 'v')])
    return

def register_Ns3RushattackdsrRushattackdsrRouting_methods(root_module, cls):
    ## rushattackdsr-routing.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRouting::RushattackdsrRouting(ns3::rushattackdsr::RushattackdsrRouting const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrRouting const &', 'arg0')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRouting::RushattackdsrRouting() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): uint16_t ns3::rushattackdsr::RushattackdsrRouting::AddAckReqHeader(ns3::Ptr<ns3::Packet> & packet, ns3::Ipv4Address nextHop) [member function]
    cls.add_method('AddAckReqHeader', 
                   'uint16_t', 
                   [param('ns3::Ptr< ns3::Packet > &', 'packet'), param('ns3::Ipv4Address', 'nextHop')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrRouting::AddRoute(ns3::rushattackdsr::RushattackdsrRouteCacheEntry & rt) [member function]
    cls.add_method('AddRoute', 
                   'bool', 
                   [param('ns3::rushattackdsr::RushattackdsrRouteCacheEntry &', 'rt')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrRouting::AddRoute_Link(ns3::rushattackdsr::RushattackdsrRouteCacheEntry::IP_VECTOR nodelist, ns3::Ipv4Address source) [member function]
    cls.add_method('AddRoute_Link', 
                   'bool', 
                   [param('std::vector< ns3::Ipv4Address >', 'nodelist'), param('ns3::Ipv4Address', 'source')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): int64_t ns3::rushattackdsr::RushattackdsrRouting::AssignStreams(int64_t stream) [member function]
    cls.add_method('AssignStreams', 
                   'int64_t', 
                   [param('int64_t', 'stream')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::CallCancelPacketTimer(uint16_t ackId, ns3::Ipv4Header const & ipv4Header, ns3::Ipv4Address realSrc, ns3::Ipv4Address realDst) [member function]
    cls.add_method('CallCancelPacketTimer', 
                   'void', 
                   [param('uint16_t', 'ackId'), param('ns3::Ipv4Header const &', 'ipv4Header'), param('ns3::Ipv4Address', 'realSrc'), param('ns3::Ipv4Address', 'realDst')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::CancelLinkPacketTimer(ns3::rushattackdsr::RushattackdsrMaintainBuffEntry & mb) [member function]
    cls.add_method('CancelLinkPacketTimer', 
                   'void', 
                   [param('ns3::rushattackdsr::RushattackdsrMaintainBuffEntry &', 'mb')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::CancelNetworkPacketTimer(ns3::rushattackdsr::RushattackdsrMaintainBuffEntry & mb) [member function]
    cls.add_method('CancelNetworkPacketTimer', 
                   'void', 
                   [param('ns3::rushattackdsr::RushattackdsrMaintainBuffEntry &', 'mb')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::CancelPacketAllTimer(ns3::rushattackdsr::RushattackdsrMaintainBuffEntry & mb) [member function]
    cls.add_method('CancelPacketAllTimer', 
                   'void', 
                   [param('ns3::rushattackdsr::RushattackdsrMaintainBuffEntry &', 'mb')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::CancelPacketTimerNextHop(ns3::Ipv4Address nextHop, uint8_t protocol) [member function]
    cls.add_method('CancelPacketTimerNextHop', 
                   'void', 
                   [param('ns3::Ipv4Address', 'nextHop'), param('uint8_t', 'protocol')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::CancelPassivePacketTimer(ns3::rushattackdsr::RushattackdsrMaintainBuffEntry & mb) [member function]
    cls.add_method('CancelPassivePacketTimer', 
                   'void', 
                   [param('ns3::rushattackdsr::RushattackdsrMaintainBuffEntry &', 'mb')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrRouting::CancelPassiveTimer(ns3::Ptr<ns3::Packet> packet, ns3::Ipv4Address source, ns3::Ipv4Address destination, uint8_t segsLeft) [member function]
    cls.add_method('CancelPassiveTimer', 
                   'bool', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('ns3::Ipv4Address', 'source'), param('ns3::Ipv4Address', 'destination'), param('uint8_t', 'segsLeft')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::CancelRreqTimer(ns3::Ipv4Address dst, bool isRemove) [member function]
    cls.add_method('CancelRreqTimer', 
                   'void', 
                   [param('ns3::Ipv4Address', 'dst'), param('bool', 'isRemove')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::CheckSendBuffer() [member function]
    cls.add_method('CheckSendBuffer', 
                   'void', 
                   [])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::DeleteAllRoutesIncludeLink(ns3::Ipv4Address errorSrc, ns3::Ipv4Address unreachNode, ns3::Ipv4Address node) [member function]
    cls.add_method('DeleteAllRoutesIncludeLink', 
                   'void', 
                   [param('ns3::Ipv4Address', 'errorSrc'), param('ns3::Ipv4Address', 'unreachNode'), param('ns3::Ipv4Address', 'node')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrRouting::FindSourceEntry(ns3::Ipv4Address src, ns3::Ipv4Address dst, uint16_t id) [member function]
    cls.add_method('FindSourceEntry', 
                   'bool', 
                   [param('ns3::Ipv4Address', 'src'), param('ns3::Ipv4Address', 'dst'), param('uint16_t', 'id')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::ForwardErrPacket(ns3::rushattackdsr::RushattackdsrOptionRerrUnreachHeader & rerr, ns3::rushattackdsr::RushattackdsrOptionSRHeader & sourceRoute, ns3::Ipv4Address nextHop, uint8_t protocol, ns3::Ptr<ns3::Ipv4Route> route) [member function]
    cls.add_method('ForwardErrPacket', 
                   'void', 
                   [param('ns3::rushattackdsr::RushattackdsrOptionRerrUnreachHeader &', 'rerr'), param('ns3::rushattackdsr::RushattackdsrOptionSRHeader &', 'sourceRoute'), param('ns3::Ipv4Address', 'nextHop'), param('uint8_t', 'protocol'), param('ns3::Ptr< ns3::Ipv4Route >', 'route')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::ForwardPacket(ns3::Ptr<const ns3::Packet> packet, ns3::rushattackdsr::RushattackdsrOptionSRHeader & sourceRoute, ns3::Ipv4Header const & ipv4Header, ns3::Ipv4Address source, ns3::Ipv4Address destination, ns3::Ipv4Address targetAddress, uint8_t protocol, ns3::Ptr<ns3::Ipv4Route> route) [member function]
    cls.add_method('ForwardPacket', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet const >', 'packet'), param('ns3::rushattackdsr::RushattackdsrOptionSRHeader &', 'sourceRoute'), param('ns3::Ipv4Header const &', 'ipv4Header'), param('ns3::Ipv4Address', 'source'), param('ns3::Ipv4Address', 'destination'), param('ns3::Ipv4Address', 'targetAddress'), param('uint8_t', 'protocol'), param('ns3::Ptr< ns3::Ipv4Route >', 'route')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): ns3::IpL4Protocol::DownTargetCallback ns3::rushattackdsr::RushattackdsrRouting::GetDownTarget() const [member function]
    cls.add_method('GetDownTarget', 
                   'ns3::IpL4Protocol::DownTargetCallback', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-routing.h (module 'rushattackdsr'): ns3::IpL4Protocol::DownTargetCallback6 ns3::rushattackdsr::RushattackdsrRouting::GetDownTarget6() const [member function]
    cls.add_method('GetDownTarget6', 
                   'ns3::IpL4Protocol::DownTargetCallback6', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-routing.h (module 'rushattackdsr'): std::vector<std::basic_string<char>, std::allocator<std::basic_string<char> > > ns3::rushattackdsr::RushattackdsrRouting::GetElementsFromContext(std::string context) [member function]
    cls.add_method('GetElementsFromContext', 
                   'std::vector< std::string >', 
                   [param('std::string', 'context')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): uint16_t ns3::rushattackdsr::RushattackdsrRouting::GetIDfromIP(ns3::Ipv4Address address) [member function]
    cls.add_method('GetIDfromIP', 
                   'uint16_t', 
                   [param('ns3::Ipv4Address', 'address')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrRouting::GetIPfromID(uint16_t id) [member function]
    cls.add_method('GetIPfromID', 
                   'ns3::Ipv4Address', 
                   [param('uint16_t', 'id')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrRouting::GetIPfromMAC(ns3::Mac48Address address) [member function]
    cls.add_method('GetIPfromMAC', 
                   'ns3::Ipv4Address', 
                   [param('ns3::Mac48Address', 'address')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): ns3::Ptr<ns3::NetDevice> ns3::rushattackdsr::RushattackdsrRouting::GetNetDeviceFromContext(std::string context) [member function]
    cls.add_method('GetNetDeviceFromContext', 
                   'ns3::Ptr< ns3::NetDevice >', 
                   [param('std::string', 'context')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): ns3::Ptr<ns3::Node> ns3::rushattackdsr::RushattackdsrRouting::GetNode() const [member function]
    cls.add_method('GetNode', 
                   'ns3::Ptr< ns3::Node >', 
                   [], 
                   is_const=True)
    ## rushattackdsr-routing.h (module 'rushattackdsr'): ns3::Ptr<ns3::Node> ns3::rushattackdsr::RushattackdsrRouting::GetNodeWithAddress(ns3::Ipv4Address ipv4Address) [member function]
    cls.add_method('GetNodeWithAddress', 
                   'ns3::Ptr< ns3::Node >', 
                   [param('ns3::Ipv4Address', 'ipv4Address')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): ns3::Ptr<ns3::rushattackdsr::RushattackdsrOptions> ns3::rushattackdsr::RushattackdsrRouting::GetOption(int optionNumber) [member function]
    cls.add_method('GetOption', 
                   'ns3::Ptr< ns3::rushattackdsr::RushattackdsrOptions >', 
                   [param('int', 'optionNumber')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): ns3::Ptr<ns3::rushattackdsr::RushattackdsrPassiveBuffer> ns3::rushattackdsr::RushattackdsrRouting::GetPassiveBuffer() const [member function]
    cls.add_method('GetPassiveBuffer', 
                   'ns3::Ptr< ns3::rushattackdsr::RushattackdsrPassiveBuffer >', 
                   [], 
                   is_const=True)
    ## rushattackdsr-routing.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrRouting::GetPriority(ns3::rushattackdsr::RushattackdsrMessageType messageType) [member function]
    cls.add_method('GetPriority', 
                   'uint32_t', 
                   [param('ns3::rushattackdsr::RushattackdsrMessageType', 'messageType')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): int ns3::rushattackdsr::RushattackdsrRouting::GetProtocolNumber() const [member function]
    cls.add_method('GetProtocolNumber', 
                   'int', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-routing.h (module 'rushattackdsr'): ns3::Ptr<ns3::rushattackdsr::RushattackdsrRreqTable> ns3::rushattackdsr::RushattackdsrRouting::GetRequestTable() const [member function]
    cls.add_method('GetRequestTable', 
                   'ns3::Ptr< ns3::rushattackdsr::RushattackdsrRreqTable >', 
                   [], 
                   is_const=True)
    ## rushattackdsr-routing.h (module 'rushattackdsr'): ns3::Ptr<ns3::rushattackdsr::RushattackdsrRouteCache> ns3::rushattackdsr::RushattackdsrRouting::GetRouteCache() const [member function]
    cls.add_method('GetRouteCache', 
                   'ns3::Ptr< ns3::rushattackdsr::RushattackdsrRouteCache >', 
                   [], 
                   is_const=True)
    ## rushattackdsr-routing.h (module 'rushattackdsr'): static ns3::TypeId ns3::rushattackdsr::RushattackdsrRouting::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::IncreaseRetransTimer() [member function]
    cls.add_method('IncreaseRetransTimer', 
                   'void', 
                   [])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::Insert(ns3::Ptr<ns3::rushattackdsr::RushattackdsrOptions> option) [member function]
    cls.add_method('Insert', 
                   'void', 
                   [param('ns3::Ptr< ns3::rushattackdsr::RushattackdsrOptions >', 'option')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrRouting::IsLinkCache() [member function]
    cls.add_method('IsLinkCache', 
                   'bool', 
                   [])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::LinkScheduleTimerExpire(ns3::rushattackdsr::RushattackdsrMaintainBuffEntry & mb, uint8_t protocol) [member function]
    cls.add_method('LinkScheduleTimerExpire', 
                   'void', 
                   [param('ns3::rushattackdsr::RushattackdsrMaintainBuffEntry &', 'mb'), param('uint8_t', 'protocol')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrRouting::LookupRoute(ns3::Ipv4Address id, ns3::rushattackdsr::RushattackdsrRouteCacheEntry & rt) [member function]
    cls.add_method('LookupRoute', 
                   'bool', 
                   [param('ns3::Ipv4Address', 'id'), param('ns3::rushattackdsr::RushattackdsrRouteCacheEntry &', 'rt')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::NetworkScheduleTimerExpire(ns3::rushattackdsr::RushattackdsrMaintainBuffEntry & mb, uint8_t protocol) [member function]
    cls.add_method('NetworkScheduleTimerExpire', 
                   'void', 
                   [param('ns3::rushattackdsr::RushattackdsrMaintainBuffEntry &', 'mb'), param('uint8_t', 'protocol')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::PacketNewRoute(ns3::Ptr<ns3::Packet> packet, ns3::Ipv4Address source, ns3::Ipv4Address destination, uint8_t protocol) [member function]
    cls.add_method('PacketNewRoute', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('ns3::Ipv4Address', 'source'), param('ns3::Ipv4Address', 'destination'), param('uint8_t', 'protocol')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrRouting::PassiveEntryCheck(ns3::Ptr<ns3::Packet> packet, ns3::Ipv4Address source, ns3::Ipv4Address destination, uint8_t segsLeft, uint16_t fragmentOffset, uint16_t identification, bool saveEntry) [member function]
    cls.add_method('PassiveEntryCheck', 
                   'bool', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('ns3::Ipv4Address', 'source'), param('ns3::Ipv4Address', 'destination'), param('uint8_t', 'segsLeft'), param('uint16_t', 'fragmentOffset'), param('uint16_t', 'identification'), param('bool', 'saveEntry')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::PassiveScheduleTimerExpire(ns3::rushattackdsr::RushattackdsrMaintainBuffEntry & mb, uint8_t protocol) [member function]
    cls.add_method('PassiveScheduleTimerExpire', 
                   'void', 
                   [param('ns3::rushattackdsr::RushattackdsrMaintainBuffEntry &', 'mb'), param('uint8_t', 'protocol')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::PrintVector(std::vector<ns3::Ipv4Address, std::allocator<ns3::Ipv4Address> > & vec) [member function]
    cls.add_method('PrintVector', 
                   'void', 
                   [param('std::vector< ns3::Ipv4Address > &', 'vec')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::PriorityScheduler(uint32_t priority, bool continueWithFirst) [member function]
    cls.add_method('PriorityScheduler', 
                   'void', 
                   [param('uint32_t', 'priority'), param('bool', 'continueWithFirst')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrRouting::Process(ns3::Ptr<ns3::Packet> & packet, ns3::Ipv4Header const & ipv4Header, ns3::Ipv4Address dst, uint8_t * nextHeader, uint8_t protocol, bool & isDropped) [member function]
    cls.add_method('Process', 
                   'uint8_t', 
                   [param('ns3::Ptr< ns3::Packet > &', 'packet'), param('ns3::Ipv4Header const &', 'ipv4Header'), param('ns3::Ipv4Address', 'dst'), param('uint8_t *', 'nextHeader'), param('uint8_t', 'protocol'), param('bool &', 'isDropped')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): ns3::IpL4Protocol::RxStatus ns3::rushattackdsr::RushattackdsrRouting::Receive(ns3::Ptr<ns3::Packet> p, ns3::Ipv4Header const & header, ns3::Ptr<ns3::Ipv4Interface> incomingInterface) [member function]
    cls.add_method('Receive', 
                   'ns3::IpL4Protocol::RxStatus', 
                   [param('ns3::Ptr< ns3::Packet >', 'p'), param('ns3::Ipv4Header const &', 'header'), param('ns3::Ptr< ns3::Ipv4Interface >', 'incomingInterface')], 
                   is_virtual=True)
    ## rushattackdsr-routing.h (module 'rushattackdsr'): ns3::IpL4Protocol::RxStatus ns3::rushattackdsr::RushattackdsrRouting::Receive(ns3::Ptr<ns3::Packet> p, ns3::Ipv6Header const & header, ns3::Ptr<ns3::Ipv6Interface> incomingInterface) [member function]
    cls.add_method('Receive', 
                   'ns3::IpL4Protocol::RxStatus', 
                   [param('ns3::Ptr< ns3::Packet >', 'p'), param('ns3::Ipv6Header const &', 'header'), param('ns3::Ptr< ns3::Ipv6Interface >', 'incomingInterface')], 
                   is_virtual=True)
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::RouteRequestTimerExpire(ns3::Ptr<ns3::Packet> packet, std::vector<ns3::Ipv4Address, std::allocator<ns3::Ipv4Address> > address, uint32_t requestId, uint8_t protocol) [member function]
    cls.add_method('RouteRequestTimerExpire', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('std::vector< ns3::Ipv4Address >', 'address'), param('uint32_t', 'requestId'), param('uint8_t', 'protocol')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::SalvagePacket(ns3::Ptr<const ns3::Packet> packet, ns3::Ipv4Address source, ns3::Ipv4Address dst, uint8_t protocol) [member function]
    cls.add_method('SalvagePacket', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet const >', 'packet'), param('ns3::Ipv4Address', 'source'), param('ns3::Ipv4Address', 'dst'), param('uint8_t', 'protocol')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::ScheduleCachedReply(ns3::Ptr<ns3::Packet> packet, ns3::Ipv4Address source, ns3::Ipv4Address destination, ns3::Ptr<ns3::Ipv4Route> route, double hops) [member function]
    cls.add_method('ScheduleCachedReply', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('ns3::Ipv4Address', 'source'), param('ns3::Ipv4Address', 'destination'), param('ns3::Ptr< ns3::Ipv4Route >', 'route'), param('double', 'hops')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::ScheduleInitialReply(ns3::Ptr<ns3::Packet> packet, ns3::Ipv4Address source, ns3::Ipv4Address nextHop, ns3::Ptr<ns3::Ipv4Route> route) [member function]
    cls.add_method('ScheduleInitialReply', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('ns3::Ipv4Address', 'source'), param('ns3::Ipv4Address', 'nextHop'), param('ns3::Ptr< ns3::Ipv4Route >', 'route')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::ScheduleInterRequest(ns3::Ptr<ns3::Packet> packet) [member function]
    cls.add_method('ScheduleInterRequest', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::ScheduleLinkPacketRetry(ns3::rushattackdsr::RushattackdsrMaintainBuffEntry & mb, uint8_t protocol) [member function]
    cls.add_method('ScheduleLinkPacketRetry', 
                   'void', 
                   [param('ns3::rushattackdsr::RushattackdsrMaintainBuffEntry &', 'mb'), param('uint8_t', 'protocol')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::ScheduleNetworkPacketRetry(ns3::rushattackdsr::RushattackdsrMaintainBuffEntry & mb, bool isFirst, uint8_t protocol) [member function]
    cls.add_method('ScheduleNetworkPacketRetry', 
                   'void', 
                   [param('ns3::rushattackdsr::RushattackdsrMaintainBuffEntry &', 'mb'), param('bool', 'isFirst'), param('uint8_t', 'protocol')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::SchedulePassivePacketRetry(ns3::rushattackdsr::RushattackdsrMaintainBuffEntry & mb, uint8_t protocol) [member function]
    cls.add_method('SchedulePassivePacketRetry', 
                   'void', 
                   [param('ns3::rushattackdsr::RushattackdsrMaintainBuffEntry &', 'mb'), param('uint8_t', 'protocol')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::ScheduleRreqRetry(ns3::Ptr<ns3::Packet> packet, std::vector<ns3::Ipv4Address, std::allocator<ns3::Ipv4Address> > address, bool nonProp, uint32_t requestId, uint8_t protocol) [member function]
    cls.add_method('ScheduleRreqRetry', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('std::vector< ns3::Ipv4Address >', 'address'), param('bool', 'nonProp'), param('uint32_t', 'requestId'), param('uint8_t', 'protocol')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::Scheduler(uint32_t priority) [member function]
    cls.add_method('Scheduler', 
                   'void', 
                   [param('uint32_t', 'priority')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrRouting::SearchNextHop(ns3::Ipv4Address ipv4Address, std::vector<ns3::Ipv4Address, std::allocator<ns3::Ipv4Address> > & vec) [member function]
    cls.add_method('SearchNextHop', 
                   'ns3::Ipv4Address', 
                   [param('ns3::Ipv4Address', 'ipv4Address'), param('std::vector< ns3::Ipv4Address > &', 'vec')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::Send(ns3::Ptr<ns3::Packet> packet, ns3::Ipv4Address source, ns3::Ipv4Address destination, uint8_t protocol, ns3::Ptr<ns3::Ipv4Route> route) [member function]
    cls.add_method('Send', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('ns3::Ipv4Address', 'source'), param('ns3::Ipv4Address', 'destination'), param('uint8_t', 'protocol'), param('ns3::Ptr< ns3::Ipv4Route >', 'route')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::SendAck(uint16_t ackId, ns3::Ipv4Address destination, ns3::Ipv4Address realSrc, ns3::Ipv4Address realDst, uint8_t protocol, ns3::Ptr<ns3::Ipv4Route> route) [member function]
    cls.add_method('SendAck', 
                   'void', 
                   [param('uint16_t', 'ackId'), param('ns3::Ipv4Address', 'destination'), param('ns3::Ipv4Address', 'realSrc'), param('ns3::Ipv4Address', 'realDst'), param('uint8_t', 'protocol'), param('ns3::Ptr< ns3::Ipv4Route >', 'route')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::SendBuffTimerExpire() [member function]
    cls.add_method('SendBuffTimerExpire', 
                   'void', 
                   [])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::SendErrorRequest(ns3::rushattackdsr::RushattackdsrOptionRerrUnreachHeader & rerr, uint8_t protocol) [member function]
    cls.add_method('SendErrorRequest', 
                   'void', 
                   [param('ns3::rushattackdsr::RushattackdsrOptionRerrUnreachHeader &', 'rerr'), param('uint8_t', 'protocol')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::SendGratuitousReply(ns3::Ipv4Address replyTo, ns3::Ipv4Address replyFrom, std::vector<ns3::Ipv4Address, std::allocator<ns3::Ipv4Address> > & nodeList, uint8_t protocol) [member function]
    cls.add_method('SendGratuitousReply', 
                   'void', 
                   [param('ns3::Ipv4Address', 'replyTo'), param('ns3::Ipv4Address', 'replyFrom'), param('std::vector< ns3::Ipv4Address > &', 'nodeList'), param('uint8_t', 'protocol')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::SendInitialRequest(ns3::Ipv4Address source, ns3::Ipv4Address destination, uint8_t protocol) [member function]
    cls.add_method('SendInitialRequest', 
                   'void', 
                   [param('ns3::Ipv4Address', 'source'), param('ns3::Ipv4Address', 'destination'), param('uint8_t', 'protocol')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::SendPacket(ns3::Ptr<ns3::Packet> packet, ns3::Ipv4Address source, ns3::Ipv4Address nextHop, uint8_t protocol) [member function]
    cls.add_method('SendPacket', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('ns3::Ipv4Address', 'source'), param('ns3::Ipv4Address', 'nextHop'), param('uint8_t', 'protocol')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::SendPacketFromBuffer(ns3::rushattackdsr::RushattackdsrOptionSRHeader const & sourceRoute, ns3::Ipv4Address nextHop, uint8_t protocol) [member function]
    cls.add_method('SendPacketFromBuffer', 
                   'void', 
                   [param('ns3::rushattackdsr::RushattackdsrOptionSRHeader const &', 'sourceRoute'), param('ns3::Ipv4Address', 'nextHop'), param('uint8_t', 'protocol')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrRouting::SendRealDown(ns3::rushattackdsr::RushattackdsrNetworkQueueEntry & newEntry) [member function]
    cls.add_method('SendRealDown', 
                   'bool', 
                   [param('ns3::rushattackdsr::RushattackdsrNetworkQueueEntry &', 'newEntry')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::SendReply(ns3::Ptr<ns3::Packet> packet, ns3::Ipv4Address source, ns3::Ipv4Address nextHop, ns3::Ptr<ns3::Ipv4Route> route) [member function]
    cls.add_method('SendReply', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('ns3::Ipv4Address', 'source'), param('ns3::Ipv4Address', 'nextHop'), param('ns3::Ptr< ns3::Ipv4Route >', 'route')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::SendRequest(ns3::Ptr<ns3::Packet> packet, ns3::Ipv4Address source) [member function]
    cls.add_method('SendRequest', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('ns3::Ipv4Address', 'source')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::SendUnreachError(ns3::Ipv4Address unreachNode, ns3::Ipv4Address destination, ns3::Ipv4Address originalDst, uint8_t salvage, uint8_t protocol) [member function]
    cls.add_method('SendUnreachError', 
                   'void', 
                   [param('ns3::Ipv4Address', 'unreachNode'), param('ns3::Ipv4Address', 'destination'), param('ns3::Ipv4Address', 'originalDst'), param('uint8_t', 'salvage'), param('uint8_t', 'protocol')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::SetDownTarget(ns3::IpL4Protocol::DownTargetCallback callback) [member function]
    cls.add_method('SetDownTarget', 
                   'void', 
                   [param('ns3::Callback< void, ns3::Ptr< ns3::Packet >, ns3::Ipv4Address, ns3::Ipv4Address, unsigned char, ns3::Ptr< ns3::Ipv4Route >, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'callback')], 
                   is_virtual=True)
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::SetDownTarget6(ns3::IpL4Protocol::DownTargetCallback6 callback) [member function]
    cls.add_method('SetDownTarget6', 
                   'void', 
                   [param('ns3::Callback< void, ns3::Ptr< ns3::Packet >, ns3::Ipv6Address, ns3::Ipv6Address, unsigned char, ns3::Ptr< ns3::Ipv6Route >, ns3::empty, ns3::empty, ns3::empty, ns3::empty >', 'callback')], 
                   is_virtual=True)
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::SetNode(ns3::Ptr<ns3::Node> node) [member function]
    cls.add_method('SetNode', 
                   'void', 
                   [param('ns3::Ptr< ns3::Node >', 'node')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::SetPassiveBuffer(ns3::Ptr<ns3::rushattackdsr::RushattackdsrPassiveBuffer> r) [member function]
    cls.add_method('SetPassiveBuffer', 
                   'void', 
                   [param('ns3::Ptr< ns3::rushattackdsr::RushattackdsrPassiveBuffer >', 'r')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::SetRequestTable(ns3::Ptr<ns3::rushattackdsr::RushattackdsrRreqTable> r) [member function]
    cls.add_method('SetRequestTable', 
                   'void', 
                   [param('ns3::Ptr< ns3::rushattackdsr::RushattackdsrRreqTable >', 'r')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): ns3::Ptr<ns3::Ipv4Route> ns3::rushattackdsr::RushattackdsrRouting::SetRoute(ns3::Ipv4Address nextHop, ns3::Ipv4Address srcAddress) [member function]
    cls.add_method('SetRoute', 
                   'ns3::Ptr< ns3::Ipv4Route >', 
                   [param('ns3::Ipv4Address', 'nextHop'), param('ns3::Ipv4Address', 'srcAddress')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::SetRouteCache(ns3::Ptr<ns3::rushattackdsr::RushattackdsrRouteCache> r) [member function]
    cls.add_method('SetRouteCache', 
                   'void', 
                   [param('ns3::Ptr< ns3::rushattackdsr::RushattackdsrRouteCache >', 'r')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrRouting::UpdateRouteEntry(ns3::Ipv4Address dst) [member function]
    cls.add_method('UpdateRouteEntry', 
                   'bool', 
                   [param('ns3::Ipv4Address', 'dst')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::UseExtends(ns3::rushattackdsr::RushattackdsrRouteCacheEntry::IP_VECTOR rt) [member function]
    cls.add_method('UseExtends', 
                   'void', 
                   [param('std::vector< ns3::Ipv4Address >', 'rt')])
    ## rushattackdsr-routing.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRouting::PROT_NUMBER [variable]
    cls.add_static_attribute('PROT_NUMBER', 'uint8_t const', is_const=True)
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::DoDispose() [member function]
    cls.add_method('DoDispose', 
                   'void', 
                   [], 
                   visibility='protected', is_virtual=True)
    ## rushattackdsr-routing.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRouting::NotifyNewAggregate() [member function]
    cls.add_method('NotifyNewAggregate', 
                   'void', 
                   [], 
                   visibility='protected', is_virtual=True)
    return

def register_Ns3RushattackdsrRushattackdsrRoutingHeader_methods(root_module, cls):
    cls.add_output_stream_operator()
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRoutingHeader::RushattackdsrRoutingHeader(ns3::rushattackdsr::RushattackdsrRoutingHeader const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrRoutingHeader const &', 'arg0')])
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRoutingHeader::RushattackdsrRoutingHeader() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrRoutingHeader::Deserialize(ns3::Buffer::Iterator start) [member function]
    cls.add_method('Deserialize', 
                   'uint32_t', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_virtual=True)
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): ns3::TypeId ns3::rushattackdsr::RushattackdsrRoutingHeader::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrRoutingHeader::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): static ns3::TypeId ns3::rushattackdsr::RushattackdsrRoutingHeader::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRoutingHeader::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-fs-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRoutingHeader::Serialize(ns3::Buffer::Iterator start) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_const=True, is_virtual=True)
    return

def register_Ns3RushattackdsrRushattackdsrRreqTable_methods(root_module, cls):
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRreqTable::RushattackdsrRreqTable(ns3::rushattackdsr::RushattackdsrRreqTable const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrRreqTable const &', 'arg0')])
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrRreqTable::RushattackdsrRreqTable() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrRreqTable::CheckUniqueRreqId(ns3::Ipv4Address dst) [member function]
    cls.add_method('CheckUniqueRreqId', 
                   'uint32_t', 
                   [param('ns3::Ipv4Address', 'dst')])
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRreqTable::FindAndUpdate(ns3::Ipv4Address dst) [member function]
    cls.add_method('FindAndUpdate', 
                   'void', 
                   [param('ns3::Ipv4Address', 'dst')])
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrRreqTable::FindSourceEntry(ns3::Ipv4Address src, ns3::Ipv4Address dst, uint16_t id) [member function]
    cls.add_method('FindSourceEntry', 
                   'bool', 
                   [param('ns3::Ipv4Address', 'src'), param('ns3::Ipv4Address', 'dst'), param('uint16_t', 'id')])
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): ns3::rushattackdsr::BlackList * ns3::rushattackdsr::RushattackdsrRreqTable::FindUnidirectional(ns3::Ipv4Address neighbor) [member function]
    cls.add_method('FindUnidirectional', 
                   'ns3::rushattackdsr::BlackList *', 
                   [param('ns3::Ipv4Address', 'neighbor')])
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrRreqTable::GetInitHopLimit() const [member function]
    cls.add_method('GetInitHopLimit', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrRreqTable::GetRreqCnt(ns3::Ipv4Address dst) [member function]
    cls.add_method('GetRreqCnt', 
                   'uint32_t', 
                   [param('ns3::Ipv4Address', 'dst')])
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrRreqTable::GetRreqIdSize() const [member function]
    cls.add_method('GetRreqIdSize', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrRreqTable::GetRreqSize() [member function]
    cls.add_method('GetRreqSize', 
                   'uint32_t', 
                   [])
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrRreqTable::GetRreqTableSize() const [member function]
    cls.add_method('GetRreqTableSize', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): static ns3::TypeId ns3::rushattackdsr::RushattackdsrRreqTable::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrRreqTable::GetUniqueRreqIdSize() const [member function]
    cls.add_method('GetUniqueRreqIdSize', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRreqTable::Invalidate() [member function]
    cls.add_method('Invalidate', 
                   'void', 
                   [])
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrRreqTable::MarkLinkAsUnidirectional(ns3::Ipv4Address neighbor, ns3::Time blacklistTimeout) [member function]
    cls.add_method('MarkLinkAsUnidirectional', 
                   'bool', 
                   [param('ns3::Ipv4Address', 'neighbor'), param('ns3::Time', 'blacklistTimeout')])
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRreqTable::PurgeNeighbor() [member function]
    cls.add_method('PurgeNeighbor', 
                   'void', 
                   [])
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRreqTable::RemoveLeastExpire() [member function]
    cls.add_method('RemoveLeastExpire', 
                   'void', 
                   [])
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRreqTable::RemoveRreqEntry(ns3::Ipv4Address dst) [member function]
    cls.add_method('RemoveRreqEntry', 
                   'void', 
                   [param('ns3::Ipv4Address', 'dst')])
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRreqTable::SetInitHopLimit(uint32_t hl) [member function]
    cls.add_method('SetInitHopLimit', 
                   'void', 
                   [param('uint32_t', 'hl')])
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRreqTable::SetRreqIdSize(uint32_t id) [member function]
    cls.add_method('SetRreqIdSize', 
                   'void', 
                   [param('uint32_t', 'id')])
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRreqTable::SetRreqTableSize(uint32_t rt) [member function]
    cls.add_method('SetRreqTableSize', 
                   'void', 
                   [param('uint32_t', 'rt')])
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrRreqTable::SetUniqueRreqIdSize(uint32_t uid) [member function]
    cls.add_method('SetUniqueRreqIdSize', 
                   'void', 
                   [param('uint32_t', 'uid')])
    return

def register_Ns3RushattackdsrRushattackdsrSendBuffEntry_methods(root_module, cls):
    cls.add_binary_comparison_operator('==')
    ## rushattackdsr-rsendbuff.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrSendBuffEntry::RushattackdsrSendBuffEntry(ns3::rushattackdsr::RushattackdsrSendBuffEntry const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrSendBuffEntry const &', 'arg0')])
    ## rushattackdsr-rsendbuff.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrSendBuffEntry::RushattackdsrSendBuffEntry(ns3::Ptr<const ns3::Packet> pa=0, ns3::Ipv4Address d=ns3::Ipv4Address(), ns3::Time exp=ns3::Simulator::Now(), uint8_t p=0) [constructor]
    cls.add_constructor([param('ns3::Ptr< ns3::Packet const >', 'pa', default_value='0'), param('ns3::Ipv4Address', 'd', default_value='ns3::Ipv4Address()'), param('ns3::Time', 'exp', default_value='ns3::Simulator::Now()'), param('uint8_t', 'p', default_value='0')])
    ## rushattackdsr-rsendbuff.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrSendBuffEntry::GetDestination() const [member function]
    cls.add_method('GetDestination', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rsendbuff.h (module 'rushattackdsr'): ns3::Time ns3::rushattackdsr::RushattackdsrSendBuffEntry::GetExpireTime() const [member function]
    cls.add_method('GetExpireTime', 
                   'ns3::Time', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rsendbuff.h (module 'rushattackdsr'): ns3::Ptr<const ns3::Packet> ns3::rushattackdsr::RushattackdsrSendBuffEntry::GetPacket() const [member function]
    cls.add_method('GetPacket', 
                   'ns3::Ptr< ns3::Packet const >', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rsendbuff.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrSendBuffEntry::GetProtocol() const [member function]
    cls.add_method('GetProtocol', 
                   'uint8_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rsendbuff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrSendBuffEntry::SetDestination(ns3::Ipv4Address d) [member function]
    cls.add_method('SetDestination', 
                   'void', 
                   [param('ns3::Ipv4Address', 'd')])
    ## rushattackdsr-rsendbuff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrSendBuffEntry::SetExpireTime(ns3::Time exp) [member function]
    cls.add_method('SetExpireTime', 
                   'void', 
                   [param('ns3::Time', 'exp')])
    ## rushattackdsr-rsendbuff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrSendBuffEntry::SetPacket(ns3::Ptr<const ns3::Packet> p) [member function]
    cls.add_method('SetPacket', 
                   'void', 
                   [param('ns3::Ptr< ns3::Packet const >', 'p')])
    ## rushattackdsr-rsendbuff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrSendBuffEntry::SetProtocol(uint8_t p) [member function]
    cls.add_method('SetProtocol', 
                   'void', 
                   [param('uint8_t', 'p')])
    return

def register_Ns3RushattackdsrRushattackdsrSendBuffer_methods(root_module, cls):
    ## rushattackdsr-rsendbuff.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrSendBuffer::RushattackdsrSendBuffer(ns3::rushattackdsr::RushattackdsrSendBuffer const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrSendBuffer const &', 'arg0')])
    ## rushattackdsr-rsendbuff.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrSendBuffer::RushattackdsrSendBuffer() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-rsendbuff.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrSendBuffer::Dequeue(ns3::Ipv4Address dst, ns3::rushattackdsr::RushattackdsrSendBuffEntry & entry) [member function]
    cls.add_method('Dequeue', 
                   'bool', 
                   [param('ns3::Ipv4Address', 'dst'), param('ns3::rushattackdsr::RushattackdsrSendBuffEntry &', 'entry')])
    ## rushattackdsr-rsendbuff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrSendBuffer::DropPacketWithDst(ns3::Ipv4Address dst) [member function]
    cls.add_method('DropPacketWithDst', 
                   'void', 
                   [param('ns3::Ipv4Address', 'dst')])
    ## rushattackdsr-rsendbuff.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrSendBuffer::Enqueue(ns3::rushattackdsr::RushattackdsrSendBuffEntry & entry) [member function]
    cls.add_method('Enqueue', 
                   'bool', 
                   [param('ns3::rushattackdsr::RushattackdsrSendBuffEntry &', 'entry')])
    ## rushattackdsr-rsendbuff.h (module 'rushattackdsr'): bool ns3::rushattackdsr::RushattackdsrSendBuffer::Find(ns3::Ipv4Address dst) [member function]
    cls.add_method('Find', 
                   'bool', 
                   [param('ns3::Ipv4Address', 'dst')])
    ## rushattackdsr-rsendbuff.h (module 'rushattackdsr'): std::vector<ns3::rushattackdsr::RushattackdsrSendBuffEntry, std::allocator<ns3::rushattackdsr::RushattackdsrSendBuffEntry> > & ns3::rushattackdsr::RushattackdsrSendBuffer::GetBuffer() [member function]
    cls.add_method('GetBuffer', 
                   'std::vector< ns3::rushattackdsr::RushattackdsrSendBuffEntry > &', 
                   [])
    ## rushattackdsr-rsendbuff.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrSendBuffer::GetMaxQueueLen() const [member function]
    cls.add_method('GetMaxQueueLen', 
                   'uint32_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rsendbuff.h (module 'rushattackdsr'): ns3::Time ns3::rushattackdsr::RushattackdsrSendBuffer::GetSendBufferTimeout() const [member function]
    cls.add_method('GetSendBufferTimeout', 
                   'ns3::Time', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rsendbuff.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrSendBuffer::GetSize() [member function]
    cls.add_method('GetSize', 
                   'uint32_t', 
                   [])
    ## rushattackdsr-rsendbuff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrSendBuffer::SetMaxQueueLen(uint32_t len) [member function]
    cls.add_method('SetMaxQueueLen', 
                   'void', 
                   [param('uint32_t', 'len')])
    ## rushattackdsr-rsendbuff.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrSendBuffer::SetSendBufferTimeout(ns3::Time t) [member function]
    cls.add_method('SetSendBufferTimeout', 
                   'void', 
                   [param('ns3::Time', 't')])
    return

def register_Ns3RushattackdsrGraReplyEntry_methods(root_module, cls):
    ## rushattackdsr-gratuitous-reply-table.h (module 'rushattackdsr'): ns3::rushattackdsr::GraReplyEntry::GraReplyEntry(ns3::rushattackdsr::GraReplyEntry const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::GraReplyEntry const &', 'arg0')])
    ## rushattackdsr-gratuitous-reply-table.h (module 'rushattackdsr'): ns3::rushattackdsr::GraReplyEntry::GraReplyEntry(ns3::Ipv4Address t, ns3::Ipv4Address f, ns3::Time h) [constructor]
    cls.add_constructor([param('ns3::Ipv4Address', 't'), param('ns3::Ipv4Address', 'f'), param('ns3::Time', 'h')])
    ## rushattackdsr-gratuitous-reply-table.h (module 'rushattackdsr'): ns3::rushattackdsr::GraReplyEntry::m_gratReplyHoldoff [variable]
    cls.add_instance_attribute('m_gratReplyHoldoff', 'ns3::Time', is_const=False)
    ## rushattackdsr-gratuitous-reply-table.h (module 'rushattackdsr'): ns3::rushattackdsr::GraReplyEntry::m_hearFrom [variable]
    cls.add_instance_attribute('m_hearFrom', 'ns3::Ipv4Address', is_const=False)
    ## rushattackdsr-gratuitous-reply-table.h (module 'rushattackdsr'): ns3::rushattackdsr::GraReplyEntry::m_replyTo [variable]
    cls.add_instance_attribute('m_replyTo', 'ns3::Ipv4Address', is_const=False)
    return

def register_Ns3RushattackdsrLink_methods(root_module, cls):
    cls.add_binary_comparison_operator('<')
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::Link::Link(ns3::rushattackdsr::Link const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::Link const &', 'arg0')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::Link::Link(ns3::Ipv4Address ip1, ns3::Ipv4Address ip2) [constructor]
    cls.add_constructor([param('ns3::Ipv4Address', 'ip1'), param('ns3::Ipv4Address', 'ip2')])
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): void ns3::rushattackdsr::Link::Print() const [member function]
    cls.add_method('Print', 
                   'void', 
                   [], 
                   is_const=True)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::Link::m_high [variable]
    cls.add_instance_attribute('m_high', 'ns3::Ipv4Address', is_const=False)
    ## rushattackdsr-rcache.h (module 'rushattackdsr'): ns3::rushattackdsr::Link::m_low [variable]
    cls.add_instance_attribute('m_low', 'ns3::Ipv4Address', is_const=False)
    return

def register_Ns3RushattackdsrLinkKey_methods(root_module, cls):
    cls.add_binary_comparison_operator('<')
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::LinkKey::LinkKey() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::LinkKey::LinkKey(ns3::rushattackdsr::LinkKey const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::LinkKey const &', 'arg0')])
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::LinkKey::m_destination [variable]
    cls.add_instance_attribute('m_destination', 'ns3::Ipv4Address', is_const=False)
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::LinkKey::m_nextHop [variable]
    cls.add_instance_attribute('m_nextHop', 'ns3::Ipv4Address', is_const=False)
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::LinkKey::m_ourAdd [variable]
    cls.add_instance_attribute('m_ourAdd', 'ns3::Ipv4Address', is_const=False)
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::LinkKey::m_source [variable]
    cls.add_instance_attribute('m_source', 'ns3::Ipv4Address', is_const=False)
    return

def register_Ns3RushattackdsrNetworkKey_methods(root_module, cls):
    cls.add_binary_comparison_operator('<')
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::NetworkKey::NetworkKey() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::NetworkKey::NetworkKey(ns3::rushattackdsr::NetworkKey const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::NetworkKey const &', 'arg0')])
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::NetworkKey::m_ackId [variable]
    cls.add_instance_attribute('m_ackId', 'uint16_t', is_const=False)
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::NetworkKey::m_destination [variable]
    cls.add_instance_attribute('m_destination', 'ns3::Ipv4Address', is_const=False)
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::NetworkKey::m_nextHop [variable]
    cls.add_instance_attribute('m_nextHop', 'ns3::Ipv4Address', is_const=False)
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::NetworkKey::m_ourAdd [variable]
    cls.add_instance_attribute('m_ourAdd', 'ns3::Ipv4Address', is_const=False)
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::NetworkKey::m_source [variable]
    cls.add_instance_attribute('m_source', 'ns3::Ipv4Address', is_const=False)
    return

def register_Ns3RushattackdsrPassiveKey_methods(root_module, cls):
    cls.add_binary_comparison_operator('<')
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::PassiveKey::PassiveKey() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::PassiveKey::PassiveKey(ns3::rushattackdsr::PassiveKey const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::PassiveKey const &', 'arg0')])
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::PassiveKey::m_ackId [variable]
    cls.add_instance_attribute('m_ackId', 'uint16_t', is_const=False)
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::PassiveKey::m_destination [variable]
    cls.add_instance_attribute('m_destination', 'ns3::Ipv4Address', is_const=False)
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::PassiveKey::m_segsLeft [variable]
    cls.add_instance_attribute('m_segsLeft', 'uint8_t', is_const=False)
    ## rushattackdsr-maintain-buff.h (module 'rushattackdsr'): ns3::rushattackdsr::PassiveKey::m_source [variable]
    cls.add_instance_attribute('m_source', 'ns3::Ipv4Address', is_const=False)
    return

def register_Ns3RushattackdsrRreqTableEntry_methods(root_module, cls):
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): ns3::rushattackdsr::RreqTableEntry::RreqTableEntry() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): ns3::rushattackdsr::RreqTableEntry::RreqTableEntry(ns3::rushattackdsr::RreqTableEntry const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RreqTableEntry const &', 'arg0')])
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): ns3::rushattackdsr::RreqTableEntry::m_expire [variable]
    cls.add_instance_attribute('m_expire', 'ns3::Time', is_const=False)
    ## rushattackdsr-rreq-table.h (module 'rushattackdsr'): ns3::rushattackdsr::RreqTableEntry::m_reqNo [variable]
    cls.add_instance_attribute('m_reqNo', 'uint32_t', is_const=False)
    return

def register_Ns3RushattackdsrRushattackdsrOptionAck_methods(root_module, cls):
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionAck::RushattackdsrOptionAck(ns3::rushattackdsr::RushattackdsrOptionAck const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrOptionAck const &', 'arg0')])
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionAck::RushattackdsrOptionAck() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionAck::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrOptionAck::GetOptionNumber() const [member function]
    cls.add_method('GetOptionNumber', 
                   'uint8_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): static ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionAck::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrOptionAck::Process(ns3::Ptr<ns3::Packet> packet, ns3::Ptr<ns3::Packet> rushattackdsrP, ns3::Ipv4Address ipv4Address, ns3::Ipv4Address source, ns3::Ipv4Header const & ipv4Header, uint8_t protocol, bool & isPromisc, ns3::Ipv4Address promiscSource) [member function]
    cls.add_method('Process', 
                   'uint8_t', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('ns3::Ptr< ns3::Packet >', 'rushattackdsrP'), param('ns3::Ipv4Address', 'ipv4Address'), param('ns3::Ipv4Address', 'source'), param('ns3::Ipv4Header const &', 'ipv4Header'), param('uint8_t', 'protocol'), param('bool &', 'isPromisc'), param('ns3::Ipv4Address', 'promiscSource')], 
                   is_virtual=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionAck::OPT_NUMBER [variable]
    cls.add_static_attribute('OPT_NUMBER', 'uint8_t const', is_const=True)
    return

def register_Ns3RushattackdsrRushattackdsrOptionAckHeader_methods(root_module, cls):
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionAckHeader::RushattackdsrOptionAckHeader(ns3::rushattackdsr::RushattackdsrOptionAckHeader const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrOptionAckHeader const &', 'arg0')])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionAckHeader::RushattackdsrOptionAckHeader() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrOptionAckHeader::Deserialize(ns3::Buffer::Iterator start) [member function]
    cls.add_method('Deserialize', 
                   'uint32_t', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint16_t ns3::rushattackdsr::RushattackdsrOptionAckHeader::GetAckId() const [member function]
    cls.add_method('GetAckId', 
                   'uint16_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionHeader::Alignment ns3::rushattackdsr::RushattackdsrOptionAckHeader::GetAlignment() const [member function]
    cls.add_method('GetAlignment', 
                   'ns3::rushattackdsr::RushattackdsrOptionHeader::Alignment', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionAckHeader::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrOptionAckHeader::GetRealDst() const [member function]
    cls.add_method('GetRealDst', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::Ipv4Address ns3::rushattackdsr::RushattackdsrOptionAckHeader::GetRealSrc() const [member function]
    cls.add_method('GetRealSrc', 
                   'ns3::Ipv4Address', 
                   [], 
                   is_const=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrOptionAckHeader::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): static ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionAckHeader::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionAckHeader::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionAckHeader::Serialize(ns3::Buffer::Iterator start) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionAckHeader::SetAckId(uint16_t identification) [member function]
    cls.add_method('SetAckId', 
                   'void', 
                   [param('uint16_t', 'identification')])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionAckHeader::SetRealDst(ns3::Ipv4Address realDstAddress) [member function]
    cls.add_method('SetRealDst', 
                   'void', 
                   [param('ns3::Ipv4Address', 'realDstAddress')])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionAckHeader::SetRealSrc(ns3::Ipv4Address realSrcAddress) [member function]
    cls.add_method('SetRealSrc', 
                   'void', 
                   [param('ns3::Ipv4Address', 'realSrcAddress')])
    return

def register_Ns3RushattackdsrRushattackdsrOptionAckReq_methods(root_module, cls):
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionAckReq::RushattackdsrOptionAckReq(ns3::rushattackdsr::RushattackdsrOptionAckReq const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrOptionAckReq const &', 'arg0')])
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionAckReq::RushattackdsrOptionAckReq() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionAckReq::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrOptionAckReq::GetOptionNumber() const [member function]
    cls.add_method('GetOptionNumber', 
                   'uint8_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): static ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionAckReq::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrOptionAckReq::Process(ns3::Ptr<ns3::Packet> packet, ns3::Ptr<ns3::Packet> rushattackdsrP, ns3::Ipv4Address ipv4Address, ns3::Ipv4Address source, ns3::Ipv4Header const & ipv4Header, uint8_t protocol, bool & isPromisc, ns3::Ipv4Address promiscSource) [member function]
    cls.add_method('Process', 
                   'uint8_t', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('ns3::Ptr< ns3::Packet >', 'rushattackdsrP'), param('ns3::Ipv4Address', 'ipv4Address'), param('ns3::Ipv4Address', 'source'), param('ns3::Ipv4Header const &', 'ipv4Header'), param('uint8_t', 'protocol'), param('bool &', 'isPromisc'), param('ns3::Ipv4Address', 'promiscSource')], 
                   is_virtual=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionAckReq::OPT_NUMBER [variable]
    cls.add_static_attribute('OPT_NUMBER', 'uint8_t const', is_const=True)
    return

def register_Ns3RushattackdsrRushattackdsrOptionAckReqHeader_methods(root_module, cls):
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionAckReqHeader::RushattackdsrOptionAckReqHeader(ns3::rushattackdsr::RushattackdsrOptionAckReqHeader const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrOptionAckReqHeader const &', 'arg0')])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionAckReqHeader::RushattackdsrOptionAckReqHeader() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrOptionAckReqHeader::Deserialize(ns3::Buffer::Iterator start) [member function]
    cls.add_method('Deserialize', 
                   'uint32_t', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint16_t ns3::rushattackdsr::RushattackdsrOptionAckReqHeader::GetAckId() const [member function]
    cls.add_method('GetAckId', 
                   'uint16_t', 
                   [], 
                   is_const=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionHeader::Alignment ns3::rushattackdsr::RushattackdsrOptionAckReqHeader::GetAlignment() const [member function]
    cls.add_method('GetAlignment', 
                   'ns3::rushattackdsr::RushattackdsrOptionHeader::Alignment', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionAckReqHeader::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): uint32_t ns3::rushattackdsr::RushattackdsrOptionAckReqHeader::GetSerializedSize() const [member function]
    cls.add_method('GetSerializedSize', 
                   'uint32_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): static ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionAckReqHeader::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionAckReqHeader::Print(std::ostream & os) const [member function]
    cls.add_method('Print', 
                   'void', 
                   [param('std::ostream &', 'os')], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionAckReqHeader::Serialize(ns3::Buffer::Iterator start) const [member function]
    cls.add_method('Serialize', 
                   'void', 
                   [param('ns3::Buffer::Iterator', 'start')], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-option-header.h (module 'rushattackdsr'): void ns3::rushattackdsr::RushattackdsrOptionAckReqHeader::SetAckId(uint16_t identification) [member function]
    cls.add_method('SetAckId', 
                   'void', 
                   [param('uint16_t', 'identification')])
    return

def register_Ns3RushattackdsrRushattackdsrOptionPad1_methods(root_module, cls):
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionPad1::RushattackdsrOptionPad1(ns3::rushattackdsr::RushattackdsrOptionPad1 const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrOptionPad1 const &', 'arg0')])
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionPad1::RushattackdsrOptionPad1() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-options.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrOptionPad1::GetOptionNumber() const [member function]
    cls.add_method('GetOptionNumber', 
                   'uint8_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): static ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionPad1::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrOptionPad1::Process(ns3::Ptr<ns3::Packet> packet, ns3::Ptr<ns3::Packet> rushattackdsrP, ns3::Ipv4Address ipv4Address, ns3::Ipv4Address source, ns3::Ipv4Header const & ipv4Header, uint8_t protocol, bool & isPromisc, ns3::Ipv4Address promiscSource) [member function]
    cls.add_method('Process', 
                   'uint8_t', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('ns3::Ptr< ns3::Packet >', 'rushattackdsrP'), param('ns3::Ipv4Address', 'ipv4Address'), param('ns3::Ipv4Address', 'source'), param('ns3::Ipv4Header const &', 'ipv4Header'), param('uint8_t', 'protocol'), param('bool &', 'isPromisc'), param('ns3::Ipv4Address', 'promiscSource')], 
                   is_virtual=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionPad1::OPT_NUMBER [variable]
    cls.add_static_attribute('OPT_NUMBER', 'uint8_t const', is_const=True)
    return

def register_Ns3RushattackdsrRushattackdsrOptionPadn_methods(root_module, cls):
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionPadn::RushattackdsrOptionPadn(ns3::rushattackdsr::RushattackdsrOptionPadn const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrOptionPadn const &', 'arg0')])
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionPadn::RushattackdsrOptionPadn() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-options.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrOptionPadn::GetOptionNumber() const [member function]
    cls.add_method('GetOptionNumber', 
                   'uint8_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): static ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionPadn::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrOptionPadn::Process(ns3::Ptr<ns3::Packet> packet, ns3::Ptr<ns3::Packet> rushattackdsrP, ns3::Ipv4Address ipv4Address, ns3::Ipv4Address source, ns3::Ipv4Header const & ipv4Header, uint8_t protocol, bool & isPromisc, ns3::Ipv4Address promiscSource) [member function]
    cls.add_method('Process', 
                   'uint8_t', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('ns3::Ptr< ns3::Packet >', 'rushattackdsrP'), param('ns3::Ipv4Address', 'ipv4Address'), param('ns3::Ipv4Address', 'source'), param('ns3::Ipv4Header const &', 'ipv4Header'), param('uint8_t', 'protocol'), param('bool &', 'isPromisc'), param('ns3::Ipv4Address', 'promiscSource')], 
                   is_virtual=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionPadn::OPT_NUMBER [variable]
    cls.add_static_attribute('OPT_NUMBER', 'uint8_t const', is_const=True)
    return

def register_Ns3RushattackdsrRushattackdsrOptionRerr_methods(root_module, cls):
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionRerr::RushattackdsrOptionRerr(ns3::rushattackdsr::RushattackdsrOptionRerr const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrOptionRerr const &', 'arg0')])
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionRerr::RushattackdsrOptionRerr() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-options.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrOptionRerr::DoSendError(ns3::Ptr<ns3::Packet> p, ns3::rushattackdsr::RushattackdsrOptionRerrUnreachHeader & rerr, uint32_t rerrSize, ns3::Ipv4Address ipv4Address, uint8_t protocol) [member function]
    cls.add_method('DoSendError', 
                   'uint8_t', 
                   [param('ns3::Ptr< ns3::Packet >', 'p'), param('ns3::rushattackdsr::RushattackdsrOptionRerrUnreachHeader &', 'rerr'), param('uint32_t', 'rerrSize'), param('ns3::Ipv4Address', 'ipv4Address'), param('uint8_t', 'protocol')])
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionRerr::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrOptionRerr::GetOptionNumber() const [member function]
    cls.add_method('GetOptionNumber', 
                   'uint8_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): static ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionRerr::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrOptionRerr::Process(ns3::Ptr<ns3::Packet> packet, ns3::Ptr<ns3::Packet> rushattackdsrP, ns3::Ipv4Address ipv4Address, ns3::Ipv4Address source, ns3::Ipv4Header const & ipv4Header, uint8_t protocol, bool & isPromisc, ns3::Ipv4Address promiscSource) [member function]
    cls.add_method('Process', 
                   'uint8_t', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('ns3::Ptr< ns3::Packet >', 'rushattackdsrP'), param('ns3::Ipv4Address', 'ipv4Address'), param('ns3::Ipv4Address', 'source'), param('ns3::Ipv4Header const &', 'ipv4Header'), param('uint8_t', 'protocol'), param('bool &', 'isPromisc'), param('ns3::Ipv4Address', 'promiscSource')], 
                   is_virtual=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionRerr::OPT_NUMBER [variable]
    cls.add_static_attribute('OPT_NUMBER', 'uint8_t const', is_const=True)
    return

def register_Ns3RushattackdsrRushattackdsrOptionRrep_methods(root_module, cls):
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionRrep::RushattackdsrOptionRrep(ns3::rushattackdsr::RushattackdsrOptionRrep const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrOptionRrep const &', 'arg0')])
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionRrep::RushattackdsrOptionRrep() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionRrep::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrOptionRrep::GetOptionNumber() const [member function]
    cls.add_method('GetOptionNumber', 
                   'uint8_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): static ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionRrep::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrOptionRrep::Process(ns3::Ptr<ns3::Packet> packet, ns3::Ptr<ns3::Packet> rushattackdsrP, ns3::Ipv4Address ipv4Address, ns3::Ipv4Address source, ns3::Ipv4Header const & ipv4Header, uint8_t protocol, bool & isPromisc, ns3::Ipv4Address promiscSource) [member function]
    cls.add_method('Process', 
                   'uint8_t', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('ns3::Ptr< ns3::Packet >', 'rushattackdsrP'), param('ns3::Ipv4Address', 'ipv4Address'), param('ns3::Ipv4Address', 'source'), param('ns3::Ipv4Header const &', 'ipv4Header'), param('uint8_t', 'protocol'), param('bool &', 'isPromisc'), param('ns3::Ipv4Address', 'promiscSource')], 
                   is_virtual=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionRrep::OPT_NUMBER [variable]
    cls.add_static_attribute('OPT_NUMBER', 'uint8_t const', is_const=True)
    return

def register_Ns3RushattackdsrRushattackdsrOptionRreq_methods(root_module, cls):
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionRreq::RushattackdsrOptionRreq(ns3::rushattackdsr::RushattackdsrOptionRreq const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrOptionRreq const &', 'arg0')])
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionRreq::RushattackdsrOptionRreq() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionRreq::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrOptionRreq::GetOptionNumber() const [member function]
    cls.add_method('GetOptionNumber', 
                   'uint8_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): static ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionRreq::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrOptionRreq::Process(ns3::Ptr<ns3::Packet> packet, ns3::Ptr<ns3::Packet> rushattackdsrP, ns3::Ipv4Address ipv4Address, ns3::Ipv4Address source, ns3::Ipv4Header const & ipv4Header, uint8_t protocol, bool & isPromisc, ns3::Ipv4Address promiscSource) [member function]
    cls.add_method('Process', 
                   'uint8_t', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('ns3::Ptr< ns3::Packet >', 'rushattackdsrP'), param('ns3::Ipv4Address', 'ipv4Address'), param('ns3::Ipv4Address', 'source'), param('ns3::Ipv4Header const &', 'ipv4Header'), param('uint8_t', 'protocol'), param('bool &', 'isPromisc'), param('ns3::Ipv4Address', 'promiscSource')], 
                   is_virtual=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionRreq::OPT_NUMBER [variable]
    cls.add_static_attribute('OPT_NUMBER', 'uint8_t const', is_const=True)
    return

def register_Ns3RushattackdsrRushattackdsrOptionSR_methods(root_module, cls):
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionSR::RushattackdsrOptionSR(ns3::rushattackdsr::RushattackdsrOptionSR const & arg0) [constructor]
    cls.add_constructor([param('ns3::rushattackdsr::RushattackdsrOptionSR const &', 'arg0')])
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionSR::RushattackdsrOptionSR() [constructor]
    cls.add_constructor([])
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionSR::GetInstanceTypeId() const [member function]
    cls.add_method('GetInstanceTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrOptionSR::GetOptionNumber() const [member function]
    cls.add_method('GetOptionNumber', 
                   'uint8_t', 
                   [], 
                   is_const=True, is_virtual=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): static ns3::TypeId ns3::rushattackdsr::RushattackdsrOptionSR::GetTypeId() [member function]
    cls.add_method('GetTypeId', 
                   'ns3::TypeId', 
                   [], 
                   is_static=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): uint8_t ns3::rushattackdsr::RushattackdsrOptionSR::Process(ns3::Ptr<ns3::Packet> packet, ns3::Ptr<ns3::Packet> rushattackdsrP, ns3::Ipv4Address ipv4Address, ns3::Ipv4Address source, ns3::Ipv4Header const & ipv4Header, uint8_t protocol, bool & isPromisc, ns3::Ipv4Address promiscSource) [member function]
    cls.add_method('Process', 
                   'uint8_t', 
                   [param('ns3::Ptr< ns3::Packet >', 'packet'), param('ns3::Ptr< ns3::Packet >', 'rushattackdsrP'), param('ns3::Ipv4Address', 'ipv4Address'), param('ns3::Ipv4Address', 'source'), param('ns3::Ipv4Header const &', 'ipv4Header'), param('uint8_t', 'protocol'), param('bool &', 'isPromisc'), param('ns3::Ipv4Address', 'promiscSource')], 
                   is_virtual=True)
    ## rushattackdsr-options.h (module 'rushattackdsr'): ns3::rushattackdsr::RushattackdsrOptionSR::OPT_NUMBER [variable]
    cls.add_static_attribute('OPT_NUMBER', 'uint8_t const', is_const=True)
    return

def register_functions(root_module):
    module = root_module
    register_functions_ns3_FatalImpl(module.add_cpp_namespace('FatalImpl'), root_module)
    register_functions_ns3_Hash(module.add_cpp_namespace('Hash'), root_module)
    register_functions_ns3_TracedValueCallback(module.add_cpp_namespace('TracedValueCallback'), root_module)
    register_functions_ns3_rushattackdsr(module.add_cpp_namespace('rushattackdsr'), root_module)
    register_functions_ns3_tests(module.add_cpp_namespace('tests'), root_module)
    return

def register_functions_ns3_FatalImpl(module, root_module):
    return

def register_functions_ns3_Hash(module, root_module):
    register_functions_ns3_Hash_Function(module.add_cpp_namespace('Function'), root_module)
    return

def register_functions_ns3_Hash_Function(module, root_module):
    return

def register_functions_ns3_TracedValueCallback(module, root_module):
    return

def register_functions_ns3_rushattackdsr(module, root_module):
    return

def register_functions_ns3_tests(module, root_module):
    return

def main():
    out = FileCodeSink(sys.stdout)
    root_module = module_init()
    register_types(root_module)
    register_methods(root_module)
    register_functions(root_module)
    root_module.generate(out)

if __name__ == '__main__':
    main()

