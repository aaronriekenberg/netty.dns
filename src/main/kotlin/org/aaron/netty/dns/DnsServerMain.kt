package org.aaron.netty.dns

import io.netty.bootstrap.Bootstrap
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInitializer
import io.netty.channel.MultithreadEventLoopGroup
import io.netty.channel.SimpleChannelInboundHandler
import io.netty.channel.epoll.Epoll
import io.netty.channel.epoll.EpollDatagramChannel
import io.netty.channel.epoll.EpollEventLoopGroup
import io.netty.channel.kqueue.KQueue
import io.netty.channel.kqueue.KQueueDatagramChannel
import io.netty.channel.kqueue.KQueueEventLoopGroup
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.DatagramChannel
import io.netty.channel.socket.DatagramPacket
import io.netty.channel.socket.nio.NioDatagramChannel
import io.netty.handler.codec.dns.*
import io.netty.handler.logging.LogLevel
import io.netty.handler.logging.LoggingHandler
import mu.KotlinLogging
import java.net.InetSocketAddress
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ThreadLocalRandom
import java.util.concurrent.TimeUnit
import kotlin.math.max
import kotlin.reflect.KClass

private val logger = KotlinLogging.logger {}

private fun createEventLoopGroup(threads: Int = 0): MultithreadEventLoopGroup =
        when {
            Epoll.isAvailable() -> EpollEventLoopGroup(threads)
            KQueue.isAvailable() -> KQueueEventLoopGroup(threads)
            else -> NioEventLoopGroup(threads)
        }

fun datagramChannelClass(): KClass<out DatagramChannel> =
        when {
            Epoll.isAvailable() -> EpollDatagramChannel::class
            KQueue.isAvailable() -> KQueueDatagramChannel::class
            else -> NioDatagramChannel::class
        }

private val eventLoopGroup = createEventLoopGroup()

private val outgoingRawDatagramChannel = Bootstrap()
        .group(eventLoopGroup)
        .channel(datagramChannelClass().java)
        .handler(object : ChannelInitializer<DatagramChannel>() {
            override fun initChannel(datagramChannel: DatagramChannel) {
                datagramChannel.pipeline().addLast(LoggingHandler(LogLevel.DEBUG))
                datagramChannel.pipeline().addLast(DatagramDnsQueryEncoder())
                //   datagramChannel.pipeline().addLast(DatagramDnsResponseDecoder())
                datagramChannel.pipeline().addLast(OutgoingRawDNSResponseHandler())
            }
        }).bind(0).sync().channel()!!

private val outgoingRawDatagramChannelLocalAddress = outgoingRawDatagramChannel.localAddress() as InetSocketAddress

private val outgoingDatagramChannel = Bootstrap()
        .group(eventLoopGroup)
        .channel(datagramChannelClass().java)
        .handler(object : ChannelInitializer<DatagramChannel>() {
            override fun initChannel(datagramChannel: DatagramChannel) {
                datagramChannel.pipeline().addLast(LoggingHandler(LogLevel.DEBUG))
                datagramChannel.pipeline().addLast(DatagramDnsQueryEncoder())
                datagramChannel.pipeline().addLast(DatagramDnsResponseDecoder())
                datagramChannel.pipeline().addLast(OutgoingDNSResponseHandler())
            }
        }).bind(0).sync().channel()!!

private val outgoingDatagramChannelLocalAddress = outgoingDatagramChannel.localAddress() as InetSocketAddress

private val outgoingServerAddress = InetSocketAddress("8.8.8.8", 53)

private val dnsServerChannel = Bootstrap()
        .group(eventLoopGroup)
        .channel(datagramChannelClass().java)
        .handler(object : ChannelInitializer<DatagramChannel>() {
            override fun initChannel(datagramChannel: DatagramChannel) {
                datagramChannel.pipeline().addLast(LoggingHandler(LogLevel.DEBUG))
                datagramChannel.pipeline().addLast(DatagramDnsResponseEncoder())
                datagramChannel.pipeline().addLast(DatagramDnsQueryDecoder())
                datagramChannel.pipeline().addLast(IncomingDNSQueryHandler())
            }
        }).bind(10053).sync().channel()!!

private val dnsServerAddress = dnsServerChannel.localAddress() as InetSocketAddress

private const val pendingRequestTimeoutSeconds: Long = 10

private data class PendingServerRequestInfo(
        val incomingID: Int,
        val clientAddress: InetSocketAddress,
        val questionString: String,
        val expirationTime: Instant
) {
    fun expired(): Boolean =
                expirationTime.isBefore(Instant.now())
}

private val idToPendingServerRequestInfo = ConcurrentHashMap<Int, PendingServerRequestInfo>()

private data class ResponseCacheObject(
        val answerARecord: DnsRawRecord,
        val expirationTime: Instant
) {
    fun expired(): Boolean =
            expirationTime.isBefore(Instant.now())
}

private val questionStringToResponseCacheObject = ConcurrentHashMap<String, ResponseCacheObject>()

private const val minTTLSeconds: Long = 300

private object PeriodicTimer {
    private val scheduler = Executors.newSingleThreadScheduledExecutor()!!

    fun start() {
        logger.info { "PeriodicTimer.start" }
        scheduler.scheduleAtFixedRate(
                {
                    try {
                        logger.info { "begin timer pop pending requests = ${idToPendingServerRequestInfo.size} cache size = ${questionStringToResponseCacheObject.size}" }

                        idToPendingServerRequestInfo.entries.removeIf { it.value.expired() }
                        questionStringToResponseCacheObject.entries.removeIf { it.value.expired() }

                        logger.info { "end timer pop pending requests = ${idToPendingServerRequestInfo.size} cache size = ${questionStringToResponseCacheObject.size}" }

                    } catch (e: Exception) {
                        logger.warn(e) { "timer pop" }
                    }
                }, 10, 10, TimeUnit.SECONDS)
    }
}

private class IncomingDNSQueryHandler() : SimpleChannelInboundHandler<DatagramDnsQuery>() {

    override fun channelRead0(ctx: ChannelHandlerContext, incomingMessage: DatagramDnsQuery) {
        logger.info { "IncomingDNSQueryHandler.channelRead0 content = $incomingMessage" }

        logger.info { "id = ${incomingMessage.id()}" }
        logger.info { "opCode = ${incomingMessage.opCode()}" }
        logger.info { "isRecursionDesired = ${incomingMessage.isRecursionDesired}" }

        val questionCount = incomingMessage.count(DnsSection.QUESTION)
        logger.info { "question count = $questionCount" }

        val question = incomingMessage.recordAt<DefaultDnsQuestion>(DnsSection.QUESTION)
        logger.info { "question = $question" }

        if (question != null) {
            logger.info { "question.name = ${question.name()}" }
            logger.info { "question.dnsClass = ${question.dnsClass()}" }
            logger.info { "question.type = ${question.type()}" }

            val responseCacheObject = questionStringToResponseCacheObject[question.toString()]
            if (responseCacheObject != null) {
                logger.info { "cache hit" }

                val response = DatagramDnsResponse(dnsServerAddress, incomingMessage.sender(), incomingMessage.id())
                response.setRecursionAvailable(true)
                response.setRecursionDesired(true)
                response.setTruncated(false)
                response.setZ(incomingMessage.z())
                response.setCode(DnsResponseCode.NOERROR)
                response.setRecord(DnsSection.QUESTION, question)

                val ttlSeconds = max(responseCacheObject.expirationTime.epochSecond - Instant.now().epochSecond, 0)

                val answerCopy = DefaultDnsRawRecord(
                        responseCacheObject.answerARecord.name(),
                        responseCacheObject.answerARecord.type(),
                        responseCacheObject.answerARecord.dnsClass(),
                        ttlSeconds,
                        responseCacheObject.answerARecord.content().copy())

                response.addRecord(DnsSection.ANSWER, answerCopy)

                dnsServerChannel.writeAndFlush(response)

            } else {
                logger.info { "cache miss" }

                val outgoingID = ThreadLocalRandom.current().nextInt(1, 65536)

                val pendingServerRequestInfo = PendingServerRequestInfo(
                        incomingID = incomingMessage.id(),
                        clientAddress = incomingMessage.sender(),
                        questionString = question.toString(),
                        expirationTime = Instant.now().plusSeconds(pendingRequestTimeoutSeconds)
                )
                idToPendingServerRequestInfo[outgoingID] = pendingServerRequestInfo

                logger.info { "saved outgoingID = $outgoingID pendingServerRequestInfo = $pendingServerRequestInfo " }

                if (question.type() == DnsRecordType.A) {
                    val outgoingRequest = DatagramDnsQuery(outgoingDatagramChannelLocalAddress, outgoingServerAddress, outgoingID, incomingMessage.opCode())
                    outgoingRequest.isRecursionDesired = incomingMessage.isRecursionDesired
                    outgoingRequest.setZ(incomingMessage.z())
                    outgoingRequest.addRecord(DnsSection.QUESTION, question)
                    outgoingDatagramChannel.writeAndFlush(outgoingRequest)
                } else {
                    val outgoingRequest = DatagramDnsQuery(outgoingRawDatagramChannelLocalAddress, outgoingServerAddress, outgoingID, incomingMessage.opCode())
                    outgoingRequest.isRecursionDesired = incomingMessage.isRecursionDesired
                    outgoingRequest.setZ(incomingMessage.z())
                    outgoingRequest.addRecord(DnsSection.QUESTION, question)
                    outgoingRawDatagramChannel.writeAndFlush(outgoingRequest)
                }

            }
        }
    }

    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
        logger.warn(cause) { "exceptionCaught" }
    }
}

private class OutgoingRawDNSResponseHandler : SimpleChannelInboundHandler<DatagramPacket>() {

    override fun channelRead0(ctx: ChannelHandlerContext, dnsResponse: DatagramPacket) {
        logger.info { "OutgoingRawDNSResponseHandler.dnsResponse = $dnsResponse" }

        val dnsResponseBuffer = dnsResponse.content()
        dnsResponseBuffer.markReaderIndex()
        val incomingResponseID = dnsResponseBuffer.readUnsignedShort()
        dnsResponseBuffer.resetReaderIndex()
        logger.info { "incomingResponseID = $incomingResponseID" }

        val pendingRequestInfo = idToPendingServerRequestInfo.remove(incomingResponseID)
        logger.info { "pendingRequestInfo = $pendingRequestInfo" }

        if (pendingRequestInfo != null) {
            dnsResponseBuffer.setShort(0, pendingRequestInfo.incomingID)

            val outputPacket = DatagramPacket(dnsResponseBuffer.retainedDuplicate(), pendingRequestInfo.clientAddress)
            logger.info { "pipeline names = ${dnsServerChannel.pipeline().names()}" }
            dnsServerChannel.pipeline().context(DatagramDnsResponseEncoder::class.java).writeAndFlush(outputPacket)
            logger.info { "wrote outputPacket" }
        }
    }

    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
        logger.warn(cause) { "exceptionCaught" }
    }
}

private class OutgoingDNSResponseHandler : SimpleChannelInboundHandler<DatagramDnsResponse>() {

    override fun channelRead0(ctx: ChannelHandlerContext, dnsResponse: DatagramDnsResponse) {
        logger.info { "OutgoingDNSResponseHandler.channelRead0 dnsResponse = $dnsResponse" }

        val responseCode = dnsResponse.code()
        logger.info { "channelRead0 responseCode = $responseCode" }

        val questionSection = dnsResponse.recordAt<DnsRecord>(DnsSection.QUESTION) as? DefaultDnsQuestion
        logger.info { "questionSection = $questionSection" }

        val answerCount = dnsResponse.count(DnsSection.ANSWER)
        logger.info { "answerCount = $answerCount" }
        logger.info { "count = ${dnsResponse.count()}" }

        val id = dnsResponse.id()
        val pendingRequestInfo = idToPendingServerRequestInfo.remove(id)
        logger.info { "pendingRequestInfo = $pendingRequestInfo" }

        if (pendingRequestInfo != null) {
            val response = DatagramDnsResponse(dnsServerAddress, pendingRequestInfo.clientAddress, pendingRequestInfo.incomingID)
            response.setRecursionAvailable(true)
            response.setRecursionDesired(true)
            response.setTruncated(false)
            response.setZ(dnsResponse.z())
            response.setCode(dnsResponse.code())
            if (questionSection != null) {
                response.setRecord(DnsSection.QUESTION, questionSection)
            }
            var answerARecord: DefaultDnsRawRecord? = null
            for (i in 0 until answerCount) {
                val answer = dnsResponse.recordAt<DnsRecord>(DnsSection.ANSWER, i) as? DefaultDnsRawRecord
                logger.info { "i=$i answer=$answer" }
                if ((answer != null) && (answer.type() == DnsRecordType.A)) {
                    answerARecord = DefaultDnsRawRecord(
                            answer.name(), answer.type(), answer.dnsClass(),
                            max(minTTLSeconds, answer.timeToLive()), answer.content())
                    response.addRecord(DnsSection.ANSWER, answerARecord.copy())
                    break
                }
            }
            logger.info { "response.count(ANSWER) = ${response.count(DnsSection.ANSWER)}" }
            logger.info { "response.count() = ${response.count()}" }
            logger.info { "sending response $response" }
            logger.info { "sending answerARecord $answerARecord ttl = ${answerARecord?.timeToLive()}" }

            if ((responseCode == DnsResponseCode.NOERROR) && (answerARecord != null)) {
                val expirationTime = Instant.now().plusSeconds(answerARecord.timeToLive())
                logger.info { "expirationTime = $expirationTime" }
                val responseCacheObject = ResponseCacheObject(
                        answerARecord = answerARecord.copy(),
                        expirationTime = expirationTime
                )
                questionStringToResponseCacheObject[pendingRequestInfo.questionString] = responseCacheObject
                logger.info { "added to cache questionString = ${pendingRequestInfo.questionString} responseCacheObject = $responseCacheObject" }
            }

            dnsServerChannel.writeAndFlush(response)
        }
    }

    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
        logger.warn(cause) { "exceptionCaught" }
    }
}


private object DnsServerMain {

    fun run() {
        logger.info { "begin run" }

        logger.info { "eventLoopGroup=${eventLoopGroup.javaClass.simpleName} executorCount=${eventLoopGroup.executorCount()}" }

        PeriodicTimer.start()

        try {

            logger.info { "outgoingDatagramChannel localAddress ${outgoingDatagramChannel.localAddress()}" }

            logger.info { "outgoingRawDatagramChannel localAddress ${outgoingRawDatagramChannel.localAddress()}" }

            logger.info { "dnsServerChannel listening ${dnsServerChannel.localAddress()}" }

            dnsServerChannel.closeFuture().sync()

        } finally {
            eventLoopGroup.shutdownGracefully()
        }
    }

}

fun main() {
    DnsServerMain.run()
}