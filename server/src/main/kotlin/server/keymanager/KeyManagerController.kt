package server.keymanager

import org.springframework.http.ResponseEntity
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.CrossOrigin
import org.springframework.web.bind.annotation.PatchMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import server.keymanager.dto.PreKeyBundle
import server.keymanager.dto.UpdateOpkKeys
import server.keymanager.dto.UpdateSignedPreKeyBundle
import server.keymanager.opk.OpkService
import java.security.Principal

@CrossOrigin
@RestController
@RequestMapping(value = ["api/v1/keymanager"], produces = ["application/json"])
class KeyManagerController (
    private val keyManagerService: KeyManagerService,
    private val opkService: OpkService,
){
    @PostMapping("/updateSignedPreKey")
    fun updateSignedPreKey(
        @RequestBody updateSignedPreKeyBundle: UpdateSignedPreKeyBundle
    ): ResponseEntity<Void> {
        keyManagerService.updateSignedPreKeyBundle(updateSignedPreKeyBundle)
        return ResponseEntity.ok().build()
    }

    @PostMapping("/updateOPK")
    fun updateOPK(
        @RequestBody updateOpkKeys: UpdateOpkKeys
    ): ResponseEntity<Void> {
        opkService.updateOpkKeys(updateOpkKeys)
        return ResponseEntity.ok().build()
    }

    @PostMapping("/updatePreKeyBundle")
    fun updatePreKeyBundle(
        principal: Principal,
        @RequestBody preKeyBundle: PreKeyBundle
    ) : ResponseEntity<Void>{
        keyManagerService.updatePreKeyBundle(principal.name, preKeyBundle)

        return ResponseEntity.ok().build()
    }

}