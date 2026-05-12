package server.keymanager

import org.springframework.http.ResponseEntity
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.CrossOrigin
import org.springframework.web.bind.annotation.PatchMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import server.keymanager.dto.PreKeyBundle
import server.keymanager.dto.UpdateOpkKeys
import server.keymanager.dto.UpdateSignedPreKeyBundle
import server.keymanager.opk.OpkService

@CrossOrigin
@RestController
@RequestMapping(value = ["api/v1/keymanager"], produces = ["application/json"])
class KeyManagerController (
    private val keyManagerService: KeyManagerService,
    private val opkService: OpkService,
){
    @PostMapping("/updateSignedPreKey")
    fun updateSignedPreKey(updateSignedPreKeyBundle: UpdateSignedPreKeyBundle): ResponseEntity<Any> {
        return keyManagerService.updateSignedPreKeyBundle(updateSignedPreKeyBundle)

    }

    @PostMapping("/updateOPK")
    fun updateOPK(updateOpkKeys: UpdateOpkKeys): ResponseEntity<Any> {
        return opkService.updateOpkKeys(updateOpkKeys).let { ResponseEntity.ok().build() }
    }

    @PostMapping("/updatePreKeyBundle")
    fun updatePreKeyBundle(preKeyBundle: PreKeyBundle):ResponseEntity<Any> {
        return keyManagerService.updatePreKeyBundle(preKeyBundle)
    }


}