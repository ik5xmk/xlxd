//
//  cimrsprotocol.cpp
//  xlxd
//
//  Created by Jean-Luc Deltombe (LX3JL) on 29/10/2019.
//  Copyright © 2015 Jean-Luc Deltombe (LX3JL). All rights reserved.
//
// ----------------------------------------------------------------------------
//    This file is part of xlxd.
//
//    xlxd is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    xlxd is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
// ----------------------------------------------------------------------------

#include "main.h"
#include <string.h>
#include "ysfdefines.h"
#include "cysfutils.h"
#include "cysffich.h"
#include "cimrsclient.h"
#include "cimrsprotocol.h"
#include "creflector.h"
#include "cgatekeeper.h"

////////////////////////////////////////////////////////////////////////////////////////
// operation

bool CImrsProtocol::Init(void)
{
    bool ok;
    
    // base class
    ok = CProtocol::Init();
 
    loadDGIDFromFile();
    
    // update the reflector callsign
    m_ReflectorCallsign.PatchCallsign(0, (const uint8 *)"IMR", 3);

    // create our socket
    ok &= m_Socket.Open(IMRS_PORT);
    if ( !ok )
    {
        std::cout << "Error opening socket on port UDP" << IMRS_PORT << " on ip " << g_Reflector.GetListenIp() << std::endl;
    }
    
    // update time
    m_LastKeepaliveTime.Now();
    
    // done
    return ok;
}

void CImrsProtocol::Close(void)
{
    // base class
    CProtocol::Close();
}

////////////////////////////////////////////////////////////////////////////////////////
// task

void CImrsProtocol::Task(void)
{
    CBuffer             Buffer;
    CIp                 Ip;
    CCallsign           Callsign;
    //CYSFFICH            Fich;
    CDvHeaderPacket     *Header;
    CDvFramePacket      *Frames[5];
    uint32              Version;

    uint8 dgid[16];
    char id_set;
    char cs_str[11];

    // handle incoming packets
    if ( m_Socket.Receive(&Buffer, &Ip, 20) != -1 )
    {
        // force port
        Ip.SetPort(IMRS_PORT);
        // crack the packet
        if ( IsValidDvFramePacket(Ip, Buffer, Frames) )
        {
            //std::cout << "IMRS DV frame"  << std::endl;
            
            // handle it
            OnDvFramePacketIn(Frames[0], &Ip);
            OnDvFramePacketIn(Frames[1], &Ip);
            OnDvFramePacketIn(Frames[2], &Ip);
            OnDvFramePacketIn(Frames[3], &Ip);
            OnDvFramePacketIn(Frames[4], &Ip);
            
        }
        else if ( IsValidDvHeaderPacket(Ip, Buffer, &Header) )
        {
            //std::cout << "IMRS DV header:"  << std::endl << *Header << std::endl;
            //std::cout << "IMRS DV header:"  << std::endl;
            
            // node linked and callsign muted?
            if ( g_GateKeeper.MayTransmit(Header->GetMyCallsign(), Ip, PROTOCOL_IMRS, Header->GetRpt2Module())  )
            {
                // handle it
                OnDvHeaderPacketIn(Header, Ip);
            }
            else
            {
                delete Header;
            }
        }
        else if ( IsValidDvLastFramePacket(Ip, Buffer, Frames) )
        {
            //std::cout << "IMRS last DV frame"  << std::endl;

            // handle it
            OnDvLastFramePacketIn((CDvLastFramePacket *)Frames[0], &Ip);
        }
        else if ( IsValidPingPacket(Buffer) )
        {
            //std::cout << "IMRS ping packet from "  << Ip << std::endl;
            
            // acknowledge request
            EncodePongPacket(&Buffer);
            m_Socket.Send(Buffer, Ip, IMRS_PORT);

            // our turn
            EncodePingPacket(&Buffer);
            m_Socket.Send(Buffer, Ip, IMRS_PORT);
        }
        else if ( IsValidConnectPacket(Buffer, &Callsign, &Version) )
        {
            //std::cout << "IMRS keepalive/connect packet from " << Callsign << " at " << Ip << std::endl;
            
            // callsign authorized?
            if ( g_GateKeeper.MayLink(Callsign, Ip, PROTOCOL_IMRS) )
            {
                 // add client if needed
                CClients *clients = g_Reflector.GetClients();
                CClient *client = clients->FindClient(Callsign, Ip, PROTOCOL_IMRS);
                // client already connected ?
                if ( client == NULL )
                {
                     std::cout << "IMRS connect packet from " << Callsign << " at " << Ip << " fw version "
                               << (int)HIBYTE(HIWORD(Version)) << "."
                               << (int)LOBYTE(HIWORD(Version)) << "."
                               << (int)HIBYTE(LOWORD(Version)) << "."
                               << (int)LOBYTE(LOWORD(Version)) << std::endl;
                               
                    // create the client
                    CImrsClient *newclient = new CImrsClient(Callsign, Ip);
                    // connect to default module
                    newclient->SetReflectorModule(IMRS_DEFAULT_MODULE);
                    Callsign.GetCallsignString(cs_str); 
                    id_set = DgidToModule(GetHome(cs_str));
                    if (id_set != ' ') {
                      
                      newclient->SetReflectorModule(id_set);
                      newclient->SetModuleHome(id_set);
                      std::cout << "set DG-ID via Home file " << id_set << std::endl;
                    }
                   else { 
                     for (int i = 0; i < 16; i++)
                       dgid[i]  = Buffer.at(41 + i);
       
                     for (uint8 i = 10; i < 99; i++) {
                       if (read_dgid(dgid, i)) {
                         id_set = DgidToModule(i);
                         if (id_set != ' ') {
                         newclient->SetReflectorModule(id_set);
                         std::cout << "set DG-ID via Connect Packet " << id_set << std::endl;
                         break;
                         }
                        }
                     }
                     }
                    
                    // and append
                    clients->AddClient(newclient);
                }
                else
                {
                    client->Alive();
                }
                // and done
                g_Reflector.ReleaseClients();
            }
        }
        else
        {
            // invalid packet
            //std::cout << "IMRS packet (" << Buffer.size() << ") from " << Callsign << " at " << Ip << std::endl;
            std::cout << "IMRS packet (" << Buffer.size() << ") from " << Callsign << " at " << Ip << std::endl;
            //Buffer.DebugDump(g_Reflector.m_DebugFile);
        }
    }
    
    // handle end of streaming timeout
    CheckStreamsTimeout();
    
    // handle queue from reflector
    HandleQueue();
    
    // keep client alive
    if ( m_LastKeepaliveTime.DurationSinceNow() > IMRS_KEEPALIVE_PERIOD )
    {
        //
        HandleKeepalives();
        
        // update time
        m_LastKeepaliveTime.Now();
    }
}

////////////////////////////////////////////////////////////////////////////////////////
// streams helpers

bool CImrsProtocol::OnDvHeaderPacketIn(CDvHeaderPacket *Header, const CIp &Ip)
{
    bool newstream = false;
    
    // find the stream
    CPacketStream *stream = GetStream(Header->GetStreamId());
    if ( stream == NULL )
    {
        // no stream open yet, open a new one
        CCallsign via(Header->GetRpt1Callsign());
        
        // find this client
        CClient *client = g_Reflector.GetClients()->FindClient(Ip, PROTOCOL_IMRS);
        if ( client != NULL )
        {
            // get client callsign
            via = client->GetCallsign();
            client->ResetTimeToHome();
            // handle changing module client is linked to
            // via dgid of packet
            if ( Header->GetRpt2Module() != client->GetReflectorModule() )
            {
                std::cout << "IMRS client " << client->GetCallsign()
                          << " linking by DG-ID to module " << Header->GetRpt2Module() << std::endl;
                client->SetReflectorModule(Header->GetRpt2Module());
            }
            
            // get module it's linked to
            //Header->SetRpt2Module(client->GetReflectorModule());

            // and try to open the stream
            if ( (stream = g_Reflector.OpenStream(Header, client)) != NULL )
            {
                // keep the handle
                m_Streams.push_back(stream);
                newstream = true;
            }
        }
        // release
        g_Reflector.ReleaseClients();
        
        // update last heard
        if ( g_Reflector.IsValidModule(Header->GetRpt2Module()) )
        {
            g_Reflector.GetUsers()->Hearing(Header->GetMyCallsign(), via, Header->GetRpt2Callsign());
            g_Reflector.ReleaseUsers();
        }
        
        // delete header if needed
        if ( !newstream )
        {
            delete Header;
        }
    }
    else
    {
        // stream already open
        // skip packet, but tickle the stream
        stream->Tickle();
        // and delete packet
        delete Header;
    }
    
    // done
    return newstream;
}

////////////////////////////////////////////////////////////////////////////////////////
// queue helper

void CImrsProtocol::HandleQueue(void)
{    
    m_Queue.Lock();
    while ( !m_Queue.empty() )
    {
        // get the packet
        CPacket *packet = m_Queue.front();
        m_Queue.pop();
        
        // get our sender's id
        int iModId = g_Reflector.GetModuleIndex(packet->GetModuleId());
        
        // encode
        CBuffer buffer;
        
        // check if it's header
        if ( packet->IsDvHeader() )
        {
            // update local stream cache
            // this relies on queue feeder setting valid module id
            m_StreamsCache[iModId].m_dvHeader = CDvHeaderPacket((const CDvHeaderPacket &)*packet);
            for ( int i = 0; i < 5; i++ )
            {
                m_StreamsCache[iModId].m_dvFrames[i] = CDvFramePacket();
            }
            
            // encode it
            EncodeDvHeaderPacket((const CDvHeaderPacket &)*packet, &buffer);
        }
        // check if it's a last frame
        else if ( packet->IsLastPacket() )
        {
            // encode it
            EncodeDvLastPacket(m_StreamsCache[iModId].m_dvHeader, (const CDvLastFramePacket &)*packet, &buffer);
        }
        // otherwise, just a regular DV frame
        else
        {
            // update local stream cache or send quintet when needed
            uint8 sid = packet->GetImrsPacketSubId();
            if ( (sid >= 0) && (sid <= 4) )
            {
                //std::cout << (int)sid;
                m_StreamsCache[iModId].m_dvFrames[sid] = CDvFramePacket((const CDvFramePacket &)*packet);
                if ( sid == 4 )
                {
                    EncodeDvPacket(m_StreamsCache[iModId].m_dvHeader, m_StreamsCache[iModId].m_dvFrames, &buffer);
                }
            }
        }
        
        // send it
        if ( buffer.size() > 0 )
        {
            // and push it to all our clients linked to the module and who are not streaming in
            CClients *clients = g_Reflector.GetClients();
            int index = -1;
            CClient *client = NULL;
            while ( (client = clients->FindNextClient(PROTOCOL_IMRS, &index)) != NULL )
            {
                // is this client busy ?
                if ( !client->IsAMaster() && (client->GetReflectorModule() == packet->GetModuleId()) )
                {
                    // no, send the packet
                    m_Socket.Send(buffer, client->GetIp(), IMRS_PORT);
                    //std::cout << "sending " << buffer.size() << " bytes to " << client->GetIp() << std::endl;
                }
                
                if (client->IsAMaster() && (client->GetReflectorModule() != client->GetModuleHome()) && (client->GetModuleHome() != ' ')) {
                  client->ResetTimeToHome();
                }
                
                // as DR-2X doesn't seems to respond to keepalives when receiving a stream
                // tickle the keepalive timer here
                client->Alive();
            }
            g_Reflector.ReleaseClients();
        }
        
        // done
        delete packet;
    }
    m_Queue.Unlock();
}

////////////////////////////////////////////////////////////////////////////////////////
// keepalive helpers

void CImrsProtocol::HandleKeepalives(void)
{
    // IMRS protocol keepalive request is client tasks
    // here, just check that all clients are still alive
    // and disconnect them if not
    
    // iterate on clients
    CClients *clients = g_Reflector.GetClients();
    int index = -1;
    CClient *client = NULL;
    while ( (client = clients->FindNextClient(PROTOCOL_IMRS, &index)) != NULL )
    {
        // is this client busy ?
        if ( client->IsAMaster() )
        {
            // yes, just tickle it
            client->Alive();
        }
        // check it's still with us
        else if ( !client->IsAlive() )
        {
            // no, remove it
            std::cout << "IMRS client " << client->GetCallsign() << " keepalive timeout" << std::endl;
            clients->RemoveClient(client);
        }
        
       if ((client->GetReflectorModule() != client->GetModuleHome()) && (client->GetModuleHome() != ' ')) {
         client->IncTimeToHome(IMRS_KEEPALIVE_PERIOD);
         // std::cout << client->GetTimeToHome() << std::endl;
         if (client->GetTimeToHome() > IMRS_BACK_TO_HOME_TIME) {
         client->SetReflectorModule(client->GetModuleHome());
         client->ResetTimeToHome();
         std::cout << client->GetCallsign() << " Back to Home at module " << client->GetModuleHome() << std::endl;
         }
       }
       else{
       client->ResetTimeToHome();
       
       } 
        
    }
    g_Reflector.ReleaseClients();
}

////////////////////////////////////////////////////////////////////////////////////////
// DV packet decoding helpers

bool CImrsProtocol::IsValidPingPacket(const CBuffer &Buffer)
{
    uint8 tag[] = { 0x00,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, };

    return ( (Buffer.size() == 16) && (Buffer.Compare(tag, sizeof(tag)) == 0) );
}

bool CImrsProtocol::IsValidConnectPacket(const CBuffer &Buffer, CCallsign *Callsign, uint32 *FirmwareVersion)
{
    uint8 tag[] = { 0x00,0x2C,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    

    bool valid = false;
    if ( (Buffer.size() == 60) && (Buffer.Compare(tag, sizeof(tag)) == 0) )
    {
        Callsign->SetCallsign(Buffer.data()+26, 8);
        Callsign->SetModule(IMRS_MODULE_ID);
        valid = (Callsign->IsValid());
        *FirmwareVersion = MAKEDWORD(MAKEWORD(Buffer.at(16), Buffer.at(17)), MAKEWORD(Buffer.at(18), Buffer.at(19)));
        //std::cout << "DG-IDs " << (int)Buffer.at(58) << "," << (int)Buffer.at(59) << std::endl;
    }
    return valid;

}

bool CImrsProtocol::IsValidDvHeaderPacket(const CIp &Ip, const CBuffer &Buffer, CDvHeaderPacket **header)
{
    bool valid = false;
    *header = NULL;

    if ( (Buffer.size() == 91) && (Buffer.at(1) == 0x4B) )
    {
        // get stream id
        uint32 uiStreamId = IpToStreamId(Ip);
        
        // and payload
        CBuffer payload;
        payload.SetFromAsciiHex((const char *)(Buffer.data()+19), 12);

        // fich
        CYSFFICH Fich;
        Fich.load((uint8 *)(payload.data()+2));
        /*std::cout << "H:"
                  << (int)Fich.getDT() << ","
                  << (int)Fich.getFI() << ","
                  << (int)Fich.getCS() << ","
                  << (int)Fich.getCM() << ","
                  << (int)Fich.getMR() << ","
                  << (int)Fich.getDev() << ","
                  << (int)Fich.getSQL() << ","
                  << (int)Fich.getSQ() << ","
                  << (int)Fich.getBN() << ","
                  << (int)Fich.getBT() << ","
                  << (int)Fich.getFN() << ","
                  << (int)Fich.getFT() << std::endl;*/

        if ( (Fich.getDT() == YSF_DT_VD_MODE2) && (Fich.getFI() == YSF_FI_HEADER) )
        {
            // build DVHeader
            char sz[YSF_CALLSIGN_LENGTH+1];
            ::memcpy(sz, &(Buffer.data()[41]), YSF_CALLSIGN_LENGTH);
            sz[YSF_CALLSIGN_LENGTH] = 0;
            CCallsign csMY = CCallsign();
            csMY.SetYsfCallsign(sz);
            ::memcpy(sz, &(Buffer.data()[61]), YSF_CALLSIGN_LENGTH);
            sz[YSF_CALLSIGN_LENGTH] = 0;
            CCallsign rpt1 = CCallsign((const char *)sz);
            rpt1.SetModule(IMRS_MODULE_ID);
            CCallsign rpt2 = m_ReflectorCallsign;
            // translate dg-id to module
            rpt2.SetModule(DgidToModule(Fich.getSQ()));
            
            // and packet
            *header = new CDvHeaderPacket(csMY, CCallsign("CQCQCQ"), rpt1, rpt2, uiStreamId, 0);
            
            // debug
            #ifdef DEBUG_DUMPFILE
                CBuffer debug;
                debug.Set((uint8 *)(Buffer.data()+0), 91);
                debug.DebugDump(g_Reflector.m_DebugFile);
            #endif
        }
        
        // check validity of packets
        if ( ((*header) == NULL) || !(*header)->IsValid()  )

        {
            delete *header;
            *header = NULL;
        }
        else
        {
            valid = true;
        }
    }
    
    // done
    return valid;
}

bool CImrsProtocol::IsValidDvFramePacket(const CIp &Ip, const CBuffer &Buffer, CDvFramePacket **frames)
{
    bool valid = false;
    frames[0] = NULL;
    frames[1] = NULL;
    frames[2] = NULL;
    frames[3] = NULL;
    frames[4] = NULL;

    if ( (Buffer.size() == 181) && (Buffer.at(1) == 0xA5) )
    {
        // get stream id
        uint32 uiStreamId = IpToStreamId(Ip);

        // and payload
        CBuffer payload;
        payload.SetFromAsciiHex((const char *)(Buffer.data()+19), 162);
        
        // fid
        uint16 fid = MAKEWORD(payload.at(1), payload.at(0));
        
        // fich
        CYSFFICH Fich;
        Fich.load((uint8 *)(payload.data()+2));
        /*std::cout << "F:"
                  << (int)Fich.getDT() << ","
                  << (int)Fich.getFI() << ","
                  << (int)Fich.getBN() << ","
                  << (int)Fich.getBT() << ","
                  << (int)Fich.getFN() << ","
                  << (int)Fich.getFT() << std::endl;*/

        if ( (Fich.getDT() == YSF_DT_VD_MODE2) && (Fich.getFI() == YSF_FI_COMMUNICATIONS) )
        {
            // dch
            //CBuffer dch;
            //dch.Set((uint8 *)(payload.data()+6), 10);
            
            // ambes
            uint8   ambe0[AMBEPLUS_SIZE];
            uint8   ambe1[AMBEPLUS_SIZE];
            uint8   ambe2[AMBEPLUS_SIZE];
            uint8   ambe3[AMBEPLUS_SIZE];
            uint8   ambe4[AMBEPLUS_SIZE];
            CYsfUtils::DecodeVD2Vch((uint8 *)(payload.data()+16+0), ambe0);
            CYsfUtils::DecodeVD2Vch((uint8 *)(payload.data()+16+13), ambe1);
            CYsfUtils::DecodeVD2Vch((uint8 *)(payload.data()+16+26), ambe2);
            CYsfUtils::DecodeVD2Vch((uint8 *)(payload.data()+16+39), ambe3);
            CYsfUtils::DecodeVD2Vch((uint8 *)(payload.data()+16+52), ambe4);

            // and create frames
            frames[0] = new CDvFramePacket(ambe0, uiStreamId, Fich.getFN(), 0, fid);
            frames[1] = new CDvFramePacket(ambe1, uiStreamId, Fich.getFN(), 1, fid);
            frames[2] = new CDvFramePacket(ambe2, uiStreamId, Fich.getFN(), 2, fid);
            frames[3] = new CDvFramePacket(ambe3, uiStreamId, Fich.getFN(), 3, fid);
            frames[4] = new CDvFramePacket(ambe4, uiStreamId, Fich.getFN(), 4, fid);
            
            // debug
            //std::cout << "F:" << uiStreamId << "," << fid << "," << (int)Fich.getFN() << std::endl;
            #ifdef DEBUG_DUMPFILE
                CBuffer debug;
                debug.Set((uint8 *)(Buffer.data()+0), 181);
                debug.DebugDump(g_Reflector.m_DebugFile);
            #endif

        }
        
        // check validity of packets
        if ( (frames[0] == NULL) || !(frames[0]->IsValid()) ||
             (frames[1] == NULL) || !(frames[1]->IsValid()) ||
             (frames[2] == NULL) || !(frames[2]->IsValid()) ||
             (frames[3] == NULL) || !(frames[3]->IsValid()) ||
             (frames[4] == NULL) || !(frames[4]->IsValid()) )
        {
            delete frames[0];
            delete frames[1];
            delete frames[2];
            delete frames[3];
            delete frames[4];
            frames[0] = NULL;
            frames[1] = NULL;
            frames[2] = NULL;
            frames[3] = NULL;
            frames[4] = NULL;
        }
        else
        {
            valid = true;
        }
    }
    
    // done
    return valid;
}

bool CImrsProtocol::IsValidDvLastFramePacket(const CIp &Ip, const CBuffer &Buffer, CDvFramePacket **frame)
{
    bool valid = false;
    uint8 ambe[AMBEPLUS_SIZE];

    *frame = NULL;

    if ( (Buffer.size() == 31) && (Buffer.at(1) == 0x0F) )
    {
        // get stream id
        uint32 uiStreamId = IpToStreamId(Ip);
        
        // and payload
        CBuffer payload;
        payload.SetFromAsciiHex((const char *)(Buffer.data()+19), 12);
        
        // fid
        uint16 fid = MAKEWORD(payload.at(1), payload.at(0));

        // fich
        CYSFFICH Fich;
        Fich.load((uint8 *)(payload.data()+2));
        
        if ( (Fich.getDT() == YSF_DT_VD_MODE2) && (Fich.getFI() == YSF_FI_TERMINATOR) )
        {
            // build frame
            ::memset(ambe, 0x00, sizeof(ambe));
            *frame = new CDvLastFramePacket(ambe, uiStreamId, Fich.getFN(), 0, fid);
            /*std::cout << "L:"
                      << (int)Fich.getDT() << ","
                      << (int)Fich.getFI() << ","
                      << (int)Fich.getBN() << ","
                      << (int)Fich.getBT() << ","
                      << (int)Fich.getFN() << ","
                      << (int)Fich.getFT() << std::endl;*/

            // debug
            #ifdef DEBUG_DUMPFILE
                CBuffer debug;
                debug.Set((uint8 *)(Buffer.data()+0), 31);
                debug.DebugDump(g_Reflector.m_DebugFile);
            #endif
        }
        
        // check validity of packets
        if ( (*frame == NULL) || !((*frame)->IsValid()) )
            
        {
            delete *frame;
            *frame = NULL;
        }
        else
        {
            valid = true;
        }
    }

    // done
    return valid;
}


////////////////////////////////////////////////////////////////////////////////////////
// DV packet encoding helpers

void CImrsProtocol::EncodePingPacket(CBuffer *Buffer) const
{
    uint8 tag[] = { 0x00,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, };

    // tag
    Buffer->Set(tag, sizeof(tag));
}

void CImrsProtocol::EncodePongPacket(CBuffer *Buffer) const
{
    uint8 tag1[] = { 0x00,0x2C,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x04,0x00,0x00 };
    uint8 radioid[] = { 'G','0','g','B','J' };
    uint8 dgid[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    char  sz[YSF_CALLSIGN_LENGTH];
    uint8 dg; 
    // tag
    Buffer->Set(tag1, sizeof(tag1));
    // mac address
    Buffer->Append(g_Reflector.GetListenMac(), 6);
    // callsign
    ::memset(sz, ' ', sizeof(sz));
    g_Reflector.GetCallsign().GetCallsignString(sz);
    sz[::strlen(sz)] = ' ';
    Buffer->Append((uint8 *)sz, YSF_CALLSIGN_LENGTH);
    // radioid
    Buffer->Append(radioid, sizeof(radioid));
    // list of authorised dg-id
    // enable dg-id 2 & NBmodules
    
    set_dgid(dgid, 2);
    
    for ( int i = 0; i < (int)NB_OF_MODULES; i++ )
    {
      dg = ModuleToDgid(char ('A' + i));  
      
      if (dg != 0) {
      set_dgid(dgid, dg);
      // debug
      // std::cout << "IMRS DG-ID Enabled: " << char ('A' + i) << " --> " << (int)dg << std::endl;
      }  
        
        
    }
    
    Buffer->Append(dgid, sizeof(dgid));
    Buffer->Append((uint8)0x00, 1);
    // and dg-id
    Buffer->Append((uint8)2);
    Buffer->Append((uint8)2);
}

bool CImrsProtocol::EncodeDvHeaderPacket(const CDvHeaderPacket &Header, CBuffer *Buffer) const
{
    uint8 tag1[] = { 0x00,0x4B,0x00,0x00,0x00,0x00,0x07 };
    uint8 tag2[] = { 0x00,0x00,0x00,0x00,0x49,0x2a,0x2a };

    // tag1
    Buffer->Set(tag1, sizeof(tag1));
    
    // time
    uint32 uiTime = (uint32)Header.GetImrsPacketFrameId() * 100;
    Buffer->Append(LOBYTE(HIWORD(uiTime)));
    Buffer->Append(HIBYTE(LOWORD(uiTime)));
    Buffer->Append(LOBYTE(LOWORD(uiTime)));

    // steamid
    uint16 uiSid = Header.GetStreamId();
    Buffer->Append(HIBYTE(uiSid));
    Buffer->Append(LOBYTE(uiSid));

    // tag2
    Buffer->Append(tag2, sizeof(tag2));
    
    // fid
    uint8 fid[2];
    fid[0] = HIBYTE(Header.GetImrsPacketFrameId());
    fid[1] = LOBYTE(Header.GetImrsPacketFrameId());
    Buffer->AppendAsAsciiHex(fid, sizeof(fid));

    // fich
    CYSFFICH Fich;
    Fich.setFI(YSF_FI_HEADER);
    Fich.setCS(2U);
    Fich.setBN(0U);
    Fich.setBT(0U);
    Fich.setFN(0U);
    Fich.setFT(6U);
    Fich.setDev(0U);
    Fich.setMR(0U);
    Fich.setDT(YSF_DT_VD_MODE2);
    Fich.setSQL(0U);
    Fich.setSQ(ModuleToDgid(Header.GetModuleId()));
    Fich.setCM(1U);
    uint8 fich[4];
    Fich.data(fich);
    Buffer->AppendAsAsciiHex(fich, 4);

    // debug
    //std::cout << "H:" << uiSid << "," << Header.GetImrsPacketFrameId() << "," << uiTime << std::endl;

    // header
    Buffer->Append((uint8)' ', 60);
    
    // destination radioid
    Buffer->ReplaceAt(31+0, (uint8 *)"*****", 5);

    // source radioid
    Buffer->ReplaceAt(31+5, (uint8 *)"G0gBJ", 5);

    // source callsign = csMY
    uint8 cs[YSF_CALLSIGN_LENGTH];
    uint8 cs_id[YSF_CALLSIGN_LENGTH];
    uint8 dgid;
    
    ::memset(cs, ' ', sizeof(cs));
    Header.GetMyCallsign().GetCallsign(cs);
    
    if (IMRS_PREFIX_ENABLE) { 
    ::memset(cs_id, ' ', sizeof(cs_id));
    dgid = ModuleToDgid(Header.GetModuleId());
            
    cs_id[0] = dgid / 10 + '0';
    cs_id[1] = dgid % 10 + '0';
    cs_id[2] = '/';
    for (int i = 0; i < YSF_CALLSIGN_LENGTH-3; i++)
      cs_id[i+3] = cs[i];
    
    Buffer->ReplaceAt(31+10, cs_id, YSF_CALLSIGN_LENGTH);
    }
    else {
    Buffer->ReplaceAt(31+10, cs, YSF_CALLSIGN_LENGTH);
    }

    // downlink callsign is blank
    
    // uplink callsign = csRPT1
    ::memset(cs, ' ', sizeof(cs));
    Header.GetRpt1Callsign().GetCallsign(cs);
    Buffer->ReplaceAt(31+30, cs, YSF_CALLSIGN_LENGTH);

    // downlink radioid
    // uplink radioid
    // voip station id (relay system ID on the internet)
    
    //  transmission source radio id
    Buffer->ReplaceAt(31+55, (uint8 *)"G0gBJ", 5);

    // done
    return true;
}


bool CImrsProtocol::EncodeDvPacket(const CDvHeaderPacket &Header, const CDvFramePacket *DvFrames, CBuffer *Buffer) const
{
    uint8 tag1[] = { 0x00,0xA5,0x00,0x00,0x00,0x00,0x07 };
    uint8 tag2[] = { 0x00,0x00,0x00,0x00,0x32,0x2a,0x2a };
    
    // tag1
    Buffer->Set(tag1, sizeof(tag1));
    
    // time
    uint32 uiTime = (uint32)DvFrames[0].GetImrsPacketFrameId() * 100;
    Buffer->Append(LOBYTE(HIWORD(uiTime)));
    Buffer->Append(HIBYTE(LOWORD(uiTime)));
    Buffer->Append(LOBYTE(LOWORD(uiTime)));

     // steamid
     uint16 uiSid = Header.GetStreamId();
     Buffer->Append(HIBYTE(uiSid));
     Buffer->Append(LOBYTE(uiSid));

     // tag2
     Buffer->Append(tag2, sizeof(tag2));
    
    // fid
    uint8 fid[2];
    fid[0] = HIBYTE(DvFrames[0].GetImrsPacketFrameId());
    fid[1] = LOBYTE(DvFrames[0].GetImrsPacketFrameId());
    Buffer->AppendAsAsciiHex(fid, sizeof(fid));
   
    // sub frame id
    // todo: normally FN should be rolling from 0 to 6, but for some
    //       reasons, if done so, the DR-2X interrupt shortly the transmission
    //       after 1 second approx ????
    //uint8 uiFN = (uint8)DvFrames[0].GetImrsPacketId();
    uint8 uiFN = 0;

    // fich
    CYSFFICH Fich;
    Fich.setFI(YSF_FI_COMMUNICATIONS);
    Fich.setCS(2U);
    Fich.setBN(0U);
    Fich.setBT(0U);
    Fich.setFN(uiFN);
    Fich.setFT(6U);
    Fich.setDev(0U);
    Fich.setMR(0U);
    Fich.setDT(YSF_DT_VD_MODE2);
    Fich.setSQL(0U);
    Fich.setSQ(ModuleToDgid(Header.GetModuleId()));
    uint8 fich[4];
    Fich.data(fich);
    Buffer->AppendAsAsciiHex(fich, 4);

    // debug
    //std::cout << "F:" << uiSid << "," << DvFrames[0].GetImrsPacketFrameId() << "," << (int)DvFrames[0].GetImrsPacketId() << "," << uiTime << std::endl;

    // todo: fill with proper content if needed
    // dch -> "*****H5!RE"
    Buffer->Append((uint8*)"2A2A2A2A2A4835215245", 20);
                             
    // ambe frames
    for ( int i = 0; i < 5; i++ )
    {
        uint8 ambe[13];
        CYsfUtils::EncodeVD2Vch((unsigned char *)DvFrames[i].GetAmbePlus(), ambe);
        Buffer->AppendAsAsciiHex(ambe, 13);
    }
    
    // done
    return true;
}

bool CImrsProtocol::EncodeDvLastPacket(const CDvHeaderPacket &Header, const CDvLastFramePacket &LastFrame, CBuffer *Buffer) const
{
    uint8 tag1[] = { 0x00,0x0F,0x00,0x00,0x00,0x00,0x00 };
    uint8 tag2[] = { 0x00,0x00,0x00,0x00,0x54,0x2a,0x2a };

    // tag1
    Buffer->Set(tag1, sizeof(tag1));

    // time
    Buffer->Append((uint8)0x3e);
    Buffer->Append((uint8)0x70);
    Buffer->Append((uint8)0xf0);

    // steamid
    uint16 uiSid = Header.GetStreamId();
    Buffer->Append(HIBYTE(uiSid));
    Buffer->Append(LOBYTE(uiSid));

    // tag2
    Buffer->Append(tag2, sizeof(tag2));

    // fid
    uint8 fid[2];
    fid[0] = HIBYTE(LastFrame.GetImrsPacketFrameId());
    fid[1] = LOBYTE(LastFrame.GetImrsPacketFrameId());
    Buffer->AppendAsAsciiHex(fid, sizeof(fid));

    // fich
    CYSFFICH Fich;
    Fich.setFI(YSF_FI_TERMINATOR);
    Fich.setCS(2U);
    Fich.setBN(0U);
    Fich.setBT(0U);
    Fich.setFN(1U);
    Fich.setFT(6U);
    Fich.setDev(0U);
    Fich.setMR(0U);
    Fich.setDT(YSF_DT_VD_MODE2);
    Fich.setSQL(0U);
    Fich.setSQ(ModuleToDgid(Header.GetModuleId()));
    uint8 fich[4];
    Fich.data(fich);
    Buffer->AppendAsAsciiHex(fich, 4);

    // debug
    //std::cout << "L:" << uiSid << "," << LastFrame.GetImrsPacketFrameId() << std::endl;

    // done
    return true;
}


////////////////////////////////////////////////////////////////////////////////////////
// uiStreamId helpers

uint32 CImrsProtocol::IpToStreamId(const CIp &ip) const
{
    return ip.GetAddr() ^ (uint32)(MAKEDWORD(ip.GetPort(), ip.GetPort()));
}

////////////////////////////////////////////////////////////////////////////////////////
///// DG-ID helper

void CImrsProtocol::loadDGIDFromFile(void)
{

 char sz[256];
 char mod;
 char cid[5];
 int id;
 int i, j;
 bool error, fout_ok;

 
// load file with MOD <--> DGID
std::cout << "Load MOD <-> DGID from file" << std::endl;
for (int i = 0; i < NB_OF_MODULES; i++)
  m_DGID_MOD[i] = (uint8)0;
  
for (int i = 0; i < 100; i++)
  m_MOD_DGID[i] = (uint8)' ';

  std::ifstream file(MOD_DGID_PATH);
//  std::ofstream file_out(MOD_DGID_DB_PATH);
  error = false;
  fout_ok = false;
  if (file.is_open())
    {
      while (file.getline(sz, sizeof(sz)).good())
        {
        // std::cout << sz << std::endl;
         char* szt = TrimWhiteSpaces(sz);
//         if (file_out.is_open()) {
//         file_out << szt << std::endl;
//         fout_ok = true;
//         }
         if ((::strlen(szt) > 0) && (szt[0] != '#'))
            {
           mod = szt[0];
           if ((mod >= 'A') and (mod <= ('A'+ NB_OF_MODULES)))  
           { 
           // valid module
           for (i = 1; i < ::strlen(szt); i++)
             {
             if (szt[i] == ';')
              break; 
              }
            i++;  
            j=0;
            for ( ; i < ::strlen(szt); i++)
             {
             if (szt[i] != ';') {
              if (isdigit(szt[i]))
                cid[j++] = szt[i];
              }
              else {
              cid[j] = '\0';
              break;   
              }
           }
           
            try {
                   id = atoi(cid);
                  }
            catch (...) {
                   id = 0;
                  } 
          
           if ((id > 0) and (id < 100)) {
             m_DGID_MOD[mod-'A'] = id;
             m_MOD_DGID[id] = mod;
           //  std::cout << "MOD <--> DGID added: " << mod << " <--> " << id << std::endl;
           }
        }
    }
    
    
     }
     file.close();
//     if (fout_ok) {
//       file_out.close();
//       }
    }
    else {
    error = true;
    
    }
    
    // load default
    if (error) {
      std::cout << "no file "<< MOD_DGID_PATH << " found ... load default" << std::endl;
      for (int i = 0; i < NB_OF_MODULES; i++)
        m_DGID_MOD[i] = 10 + i;
  
    for (int i = 0; i < NB_OF_MODULES; i++)
       m_MOD_DGID[i+10] = 'A' + i;
    
    }
    
    std::cout << "IMRS MOD -> DGID Matrix:" << std::endl;
    
    for (int i = 0; i < NB_OF_MODULES; i++)
      if (m_DGID_MOD[i] > 0)
        std::cout << (char)('A' + i) << " <--> " << (int)m_DGID_MOD[i] << std::endl;
  
    std::cout << "IMRS DGID -> MOD Matrix:" << std::endl;
  
    for (int i = 0; i < 100; i++)
      if (m_MOD_DGID[i] >= 'A')
        std::cout << (int)i << " <--> " << (char)m_MOD_DGID[i] << std::endl;

}


char CImrsProtocol::DgidToModule(uint8 uiDgid) const
{
    char cModule = ' ';
    cModule = m_MOD_DGID[uiDgid];           
    return cModule;

}


uint8 CImrsProtocol::ModuleToDgid(char cModule) const
{
    uint8 uiDgid = 0x00;
    uiDgid = m_DGID_MOD[cModule - 'A'];  
    return uiDgid;
}


// ### DG-ID MANAGEMENT ###

bool CImrsProtocol::read_dgid(uint8* d, uint8 n) const
{
    uint8 nby, nbi;
    nby = int(n / 8);
    nbi = n % 8;
    return d[nby] & (0x1 << nbi);
} 


void CImrsProtocol::set_dgid(uint8* d, uint8 n) const 
{
    uint8 nby, nbi;
    nby = int(n / 8);
    nbi = n % 8;
    d[nby] = d[nby] | (0x1 << nbi);
}

void CImrsProtocol::reset_dgid(uint8* d, uint8 n) const  
{
    uint8 nby, nbi;
    nby = int(n / 8);
    nbi = n % 8;
    d[nby] = d[nby] & ~(0x1 << nbi);
}


char* CImrsProtocol::TrimWhiteSpaces(char* str) const
{
    char* end;

    // Trim leading space & tabs
    while ((*str == ' ') || (*str == '\t')) str++;

    // All spaces?
    if (*str == 0)
        return str;

    // Trim trailing space, tab or lf
    end = str + ::strlen(str) - 1;
    while ((end > str) && ((*end == ' ') || (*end == '\t') || (*end == '\r'))) end--;

    // Write new null terminator
    *(end + 1) = 0;

    return str;
}

uint8 CImrsProtocol::GetHome(char *call) const  
{
   bool ok = false;
    char sz[256];
    char cs[11];
    char cid[5];
    int id;
    int i, j;
    bool error;

    id = 0;
    std::ifstream file (DR2_HOME_PATH);
    error = false;
    if (file.is_open())
    {
        while (file.getline(sz, sizeof(sz)).good())
        {
            char* szt = TrimWhiteSpaces(sz);
            char* call_trim = TrimWhiteSpaces(call);
            if ((::strlen(szt) > 0) && (szt[0] != '#'))
            {
                for (i = 0; i < 10; i++) {
                    if (isalnum(szt[i])) {
                        cs[i] = szt[i];
                    }
                    if ((szt[i] == ' ') || (szt[i] == '\t')) {
                        cs[i] = '\0';
                        break;
                    }
               }
               
                if (strlen(cs) < 3)
                    error = true;

                if (strcmp(cs, call_trim) == 0) {
               
                j = 0;
                for (; i < 255; i++) {
                    if (isdigit(szt[i])) {
                        cs[j++] = szt[i];
                    }
                    if ((j > 0) && !isdigit(szt[i])) {
                        cs[j] = '\0';
                        break;

              }
                }
                //std::cout << cs << std::endl;
                //std::cout << szt << std::endl;
                  try {
                  id = atoi(cs);
                  }
                  catch (...) {
                      id = 0;
                      error = true;
                  }
              break;     
            }
           
           }

        }
          file.close();
         // std::cout << "DR2 Home letto " << std::endl;
        }

return uint8(id);
}
